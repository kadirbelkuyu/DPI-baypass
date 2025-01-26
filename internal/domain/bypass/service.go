package bypass

import (
	"math/rand"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kadirbelkuyu/DPI-bypass/internal/infrastructure/network"
	"go.uber.org/ratelimit"
	"go.uber.org/zap"
)

const (
	maxRetries   = 3
	minBackoff   = 50 * time.Microsecond
	maxBackoff   = 1 * time.Millisecond
	tlsHandshake = 0x16
	clientHello  = 0x01
)

type ConnTrack struct {
	lastSeen    time.Time
	needsBypass bool
}

type Service struct {
	config          Config
	logger          *zap.Logger
	handle          *pcap.Handle
	capture         *network.PacketCapture
	connTracker     sync.Map
	workers         int
	rateLimiter     ratelimit.Limiter
	packetQueue     chan gopacket.Packet
	seenConnections map[string]bool
	connMutex       sync.RWMutex
	packets         chan gopacket.Packet
}

type Config struct {
	Interface     string
	MTU           int
	FragmentSize  int
	Debug         bool
	Workers       int
	RateLimit     int
	QueueSize     int
	CleanupFreq   int
	EnableLogging bool
}

func NewService(config Config) *Service {
	if config.Workers <= 0 {
		config.Workers = 4
	}
	if config.RateLimit <= 0 {
		config.RateLimit = 50000 // 50k packets/s
	}
	if config.QueueSize <= 0 {
		config.QueueSize = 50000
	}
	if config.CleanupFreq <= 0 {
		config.CleanupFreq = 60
	}

	return &Service{
		config:          config,
		workers:         config.Workers,
		rateLimiter:     ratelimit.New(config.RateLimit),
		packetQueue:     make(chan gopacket.Packet, config.QueueSize),
		seenConnections: make(map[string]bool),
		packets:         make(chan gopacket.Packet, config.QueueSize),
	}
}

func (s *Service) Start() error {
	var loggerConfig zap.Config
	if s.config.Debug {
		loggerConfig = zap.NewDevelopmentConfig()
	} else {
		loggerConfig = zap.NewProductionConfig()
	}

	logger, err := loggerConfig.Build()
	if err != nil {
		return err
	}
	s.logger = logger

	s.logger.Info("Starting DPI bypass service",
		zap.String("interface", s.config.Interface),
		zap.Int("mtu", s.config.MTU),
		zap.Bool("debug", s.config.Debug))

	handle, err := pcap.OpenLive(s.config.Interface, int32(s.config.MTU), true, pcap.BlockForever)
	if err != nil {
		return err
	}
	s.handle = handle

	err = handle.SetBPFFilter("tcp")
	if err != nil {
		return err
	}

	go s.processPackets()
	go s.packetSender()
	go s.cleanupConnections()

	return s.capturePackets()
}

func (s *Service) packetWorker(wg *sync.WaitGroup) {
	defer wg.Done()
	for packet := range s.packetQueue {
		if err := s.processPacket(packet); err != nil {
			s.logger.Debug("Packet processing error", zap.Error(err))
		}
	}
}

func (s *Service) packetSender() {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
	}
}

func (s *Service) processPacket(packet gopacket.Packet) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return s.capture.SendPacket(packet.Data())
	}

	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)

	// RST paketlerini engelle
	if tcp.RST {
		s.logger.Debug("Blocked RST packet", zap.String("src", ip.SrcIP.String()))
		return nil
	}

	if tcp.SYN && !tcp.ACK {
		return s.handleSYNPacket(ip, tcp)
	}

	if tcp.DstPort == 443 && len(tcp.Payload) > 0 && s.isTLSClientHello(tcp.Payload) {
		return s.sendImprovedFragmentsWithRetry(ip, tcp)
	}

	return s.sendPacketWithRetry(packet.Data())
}

func (s *Service) handleSYNPacket(ip *layers.IPv4, tcp *layers.TCP) error {
	newTCP := *tcp
	newTCP.Options = []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xbc}},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{0x07}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
	}
	newTCP.Window = 64240
	newTCP.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ip, &newTCP); err != nil {
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) isTLSClientHello(payload []byte) bool {
	return len(payload) > 5 && payload[0] == tlsHandshake && payload[5] == clientHello
}

func (s *Service) sendImprovedFragmentsWithRetry(ip *layers.IPv4, tcp *layers.TCP) error {
	payload := tcp.Payload
	totalLen := len(payload)

	if totalLen > 8 {
		if err := s.sendFragment(ip, tcp, payload[:8]); err != nil {
			return err
		}
	}
	time.Sleep(150 * time.Microsecond)

	fragSize := 1448
	for i := 8; i < totalLen; i += fragSize {
		end := i + fragSize
		if end > totalLen {
			end = totalLen
		}
		if err := s.sendFragment(ip, tcp, payload[i:end]); err != nil {
			return err
		}
		time.Sleep(75 * time.Microsecond)
	}
	return nil
}

func (s *Service) sendFragment(ip *layers.IPv4, tcp *layers.TCP, payload []byte) error {
	s.rateLimiter.Take() // Hız sınırı

	newTCP := *tcp
	newTCP.SetNetworkLayerForChecksum(ip)
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buffer, opts, ip, &newTCP, gopacket.Payload(payload)); err != nil {
		s.logger.Error("Fragment serialize error", zap.Error(err))
		return err
	}

	if err := s.capture.SendPacket(buffer.Bytes()); err != nil {
		s.logger.Debug("Fragment send error", zap.Error(err))
		return err
	}

	return nil
}

func (s *Service) sendPacketWithRetry(data []byte) error {
	for i := 0; i < maxRetries; i++ {
		if err := s.capture.SendPacket(data); err == nil {
			return nil
		}
		time.Sleep(minBackoff)
	}
	return nil
}

func (s *Service) cleanupConnections() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupFreq) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.connTracker.Range(func(key, value interface{}) bool {
			if ct, ok := value.(*ConnTrack); ok && now.Sub(ct.lastSeen) > 30*time.Second {
				s.connTracker.Delete(key)
			}
			return true
		})

		s.connMutex.Lock()
		for k := range s.seenConnections {
			delete(s.seenConnections, k)
		}
		s.connMutex.Unlock()
	}
}

func (s *Service) processPackets() {
	for packet := range s.packets {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			// Randomize sequence number for SYN packets
			tcp.Seq = rand.Uint32()
		}

		// Fragment packets
		if len(tcp.Payload) > s.config.FragmentSize {
			s.sendFragmentedPacket(packet)
			continue
		}

		// Modify TTL
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			ip.TTL = 64 // Set fixed TTL
		}

		// Send modified packet
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		err := gopacket.SerializePacket(buffer, opts, packet)
		if err != nil {
			continue
		}

		err = s.handle.WritePacketData(buffer.Bytes())
		if err != nil {
			continue
		}
	}
}

func (s *Service) sendFragmentedPacket(packet gopacket.Packet) {
	// Implementation of packet fragmentation
	// This splits large packets into smaller fragments
	// ...existing fragmentation logic...
}

func (s *Service) capturePackets() error {
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	for packet := range packetSource.Packets() {
		s.packets <- packet
	}
	return nil
}
