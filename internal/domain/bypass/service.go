package bypass

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kadirbelkuyu/DPI-bypass/internal/infrastructure/network"
	"go.uber.org/ratelimit"
	"go.uber.org/zap"
)

const (
	maxRetries = 3
	minBackoff = 50 * time.Microsecond
	maxBackoff = 1 * time.Millisecond
)

type ConnTrack struct {
	lastSeen    time.Time
	needsBypass bool
}

type Service struct {
	config          Config
	logger          *zap.Logger
	capture         *network.PacketCapture
	connTracker     sync.Map
	workers         int
	rateLimiter     ratelimit.Limiter
	packetQueue     chan gopacket.Packet
	seenConnections map[string]bool
	connMutex       sync.RWMutex
}

type Config struct {
	MTU           int
	FragmentSize  int
	Interface     string
	EnableLogging bool
	Workers       int
	RateLimit     int
	QueueSize     int
	CleanupFreq   int
}

func NewService(config Config) *Service {
	if config.Workers <= 0 {
		config.Workers = 4
	}
	if config.RateLimit <= 0 {
		config.RateLimit = 100000
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
	}
}

func (s *Service) Start() error {
	var loggerConfig zap.Config
	if s.config.EnableLogging {
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
		zap.Bool("debug", s.config.EnableLogging))

	s.capture, err = network.NewPacketCapture(s.config.Interface)
	if err != nil {
		s.logger.Error("Failed to initialize packet capture", zap.Error(err))
		return err
	}

	var wg sync.WaitGroup
	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go s.packetWorker(&wg)
	}

	go s.packetSender()

	go s.cleanupConnections()

	return s.capture.Start(func(packet gopacket.Packet) {
		select {
		case s.packetQueue <- packet:
		default:
		}
	})
}

func (s *Service) packetWorker(wg *sync.WaitGroup) {
	defer wg.Done()

	for packet := range s.packetQueue {
		if err := s.processPacket(packet); err != nil {
			if err.Error() != "send: No buffer space available" {
				s.logger.Debug("Packet processing error", zap.Error(err))
			}
			time.Sleep(minBackoff)
		}
	}
}

func (s *Service) packetSender() {
	const batchSize = 100
	batch := make([][]byte, 0, batchSize)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if len(batch) > 0 {
			for _, packetData := range batch {
				if err := s.capture.SendPacket(packetData); err != nil {
					if err.Error() != "send: No buffer space available" {
						s.logger.Error("Failed to send packet", zap.Error(err))
					}
					time.Sleep(time.Millisecond)
				}
			}
			batch = batch[:0]
		}
		time.Sleep(time.Millisecond)
	}
}

func (s *Service) processPacket(packet gopacket.Packet) error {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if ipLayer == nil || tcpLayer == nil {
		return s.capture.SendPacket(packet.Data())
	}

	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)

	if tcp.DstPort == 443 && len(tcp.Payload) > 0 && s.isTLSClientHello(tcp.Payload) {
		s.logger.Debug("Found TLS Client Hello, applying fragmentation")
		return s.sendImprovedFragmentsWithRetry(ip, tcp)
	}

	return s.sendPacketWithRetry(packet.Data())
}

func (s *Service) sendPacketWithRetry(data []byte) error {
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if err := s.capture.SendPacket(data); err != nil {
			if err.Error() == "send: No buffer space available" {
				backoff := time.Duration(i+1) * minBackoff
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				time.Sleep(backoff)
				lastErr = err
				continue
			}
			return err
		}
		return nil
	}
	return lastErr
}

func (s *Service) sendImprovedFragmentsWithRetry(ip *layers.IPv4, tcp *layers.TCP) error {
	payload := tcp.Payload
	totalLen := len(payload)

	if totalLen > 0 {
		firstFrag := s.createFragment(ip, tcp, payload[:1])
		if err := s.sendPacketWithRetry(firstFrag); err != nil {
			return err
		}
	}
	time.Sleep(50 * time.Microsecond)

	fragSize := 32
	for i := 1; i < totalLen; i += fragSize {
		end := i + fragSize
		if end > totalLen {
			end = totalLen
		}
		frag := s.createFragment(ip, tcp, payload[i:end])
		if err := s.sendPacketWithRetry(frag); err != nil {
			return err
		}
		time.Sleep(25 * time.Microsecond)
	}

	return nil
}

func (s *Service) calculateOptimalFragmentSize(payloadSize int) int {
	switch {
	case payloadSize > 8000:
		return 512
	case payloadSize > 4000:
		return 256
	case payloadSize > 2000:
		return 128
	default:
		return 64
	}
}

func (s *Service) sendFragment(ip *layers.IPv4, tcp *layers.TCP, payload []byte) error {
	newTCP := *tcp
	newTCP.SetNetworkLayerForChecksum(ip)

	if len(payload) > 0 {
		newTCP.Seq = tcp.Seq + uint32(len(tcp.Payload)-len(payload))
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
		gopacket.Payload(payload),
	)
	if err != nil {
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) handleSYNPacket(ip *layers.IPv4, tcp *layers.TCP) error {
	newTCP := *tcp

	newTCP.Options = []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xB4},
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07},
		},
	}

	newTCP.Window = 65535
	newTCP.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
	)
	if err != nil {
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) isTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	return payload[0] == 0x16 && payload[5] == 0x01
}

func (s *Service) isHTTPSPort(port layers.TCPPort) bool {
	return port == 443
}

func (s *Service) handleDataPacket(ip *layers.IPv4, tcp *layers.TCP, packet gopacket.Packet) error {
	if err := s.sendFirstByte(ip, tcp); err != nil {
		return err
	}

	time.Sleep(time.Millisecond)

	return s.sendRemainingBytes(ip, tcp)
}

func (s *Service) sendFirstByte(ip *layers.IPv4, tcp *layers.TCP) error {
	if len(tcp.Payload) == 0 {
		return nil
	}

	newTCP := *tcp
	newTCP.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
		gopacket.Payload(tcp.Payload[:1]),
	)
	if err != nil {
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) sendRemainingBytes(ip *layers.IPv4, tcp *layers.TCP) error {
	if len(tcp.Payload) <= 1 {
		return nil
	}

	newTCP := *tcp
	newTCP.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
		gopacket.Payload(tcp.Payload[1:]),
	)
	if err != nil {
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) splitAndSendPacket(ip *layers.IPv4, tcp *layers.TCP) error {
	payloadLen := len(tcp.Payload)
	if payloadLen <= 1 {
		return s.capture.SendPacket(ip.Contents)
	}

	chunkSize := 1
	for offset := 0; offset < payloadLen; offset += chunkSize {
		end := offset + chunkSize
		if end > payloadLen {
			end = payloadLen
		}

		chunk := tcp.Payload[offset:end]

		newTCP := *tcp
		newTCP.SetNetworkLayerForChecksum(ip)

		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}

		err := gopacket.SerializeLayers(buffer, opts,
			ip,
			&newTCP,
			gopacket.Payload(chunk),
		)
		if err != nil {
			continue
		}

		if err := s.capture.SendPacket(buffer.Bytes()); err != nil {
			return err
		}

		time.Sleep(time.Microsecond * 100)
	}

	return nil
}

func (s *Service) shouldLogPacket(tcp *layers.TCP, connKey string) bool {
	s.connMutex.Lock()
	defer s.connMutex.Unlock()

	if tcp.SYN && !tcp.ACK {
		s.seenConnections[connKey] = true
		return true
	}

	if tcp.FIN || tcp.RST {
		delete(s.seenConnections, connKey)
		return true
	}

	return !s.seenConnections[connKey]
}

func (s *Service) getTCPState(tcp *layers.TCP) string {
	if tcp.SYN && !tcp.ACK {
		return "New Connection"
	} else if tcp.SYN && tcp.ACK {
		return "Connection Accept"
	} else if tcp.FIN {
		return "Connection Close"
	} else if tcp.RST {
		return "Connection Reset"
	}
	return "Established"
}

func (s *Service) handleRSTPacket(ip *layers.IPv4, tcp *layers.TCP, packet gopacket.Packet) error {
	if s.isTargetPort(tcp.SrcPort) || s.isTargetPort(tcp.DstPort) {
		return nil
	}
	return s.capture.SendPacket(packet.Data())
}

func (s *Service) handleNewConnection(ip *layers.IPv4, tcp *layers.TCP, packet gopacket.Packet) error {
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	newOptions := []layers.TCPOption{
		{
			OptionType:   layers.TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x05, 0xb4},
		},
		{
			OptionType:   layers.TCPOptionKindWindowScale,
			OptionLength: 3,
			OptionData:   []byte{0x07},
		},
		{
			OptionType:   layers.TCPOptionKindSACKPermitted,
			OptionLength: 2,
		},
	}

	newTCP := *tcp
	newTCP.Options = newOptions
	newTCP.SetNetworkLayerForChecksum(ip)

	s.logger.Debug("Modifying SYN packet",
		zap.String("src", ip.SrcIP.String()),
		zap.String("dst", ip.DstIP.String()),
		zap.Uint16("sport", uint16(tcp.SrcPort)),
		zap.Uint16("dport", uint16(tcp.DstPort)))

	buffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
	)
	if err != nil {
		s.logger.Error("Failed to serialize packet", zap.Error(err))
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) handleEstablishedConnection(ip *layers.IPv4, tcp *layers.TCP, packet gopacket.Packet) error {
	if len(tcp.Payload) == 0 {
		return s.capture.SendPacket(packet.Data())
	}

	newIP := *ip
	newIP.TTL = 64

	newTCP := *tcp
	newTCP.Window = 65535
	newTCP.SetNetworkLayerForChecksum(&newIP)

	if len(tcp.Payload) > 0 {
		s.logger.Debug("Modifying established connection packet",
			zap.String("src", ip.SrcIP.String()),
			zap.String("dst", ip.DstIP.String()),
			zap.Int("payload_size", len(tcp.Payload)))
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		&newIP,
		&newTCP,
		gopacket.Payload(tcp.Payload),
	)
	if err != nil {
		s.logger.Error("Failed to serialize packet",
			zap.Error(err),
			zap.String("src", ip.SrcIP.String()),
			zap.String("dst", ip.DstIP.String()))
		return err
	}

	return s.capture.SendPacket(buffer.Bytes())
}

func (s *Service) isTargetPort(port layers.TCPPort) bool {
	return port == 80 || port == 443 || port == 8080
}

func (s *Service) shouldBypassConnection(connID network.ConnID, tcp *layers.TCP) bool {
	if tcp.DstPort == 80 || tcp.DstPort == 443 {
		if tcp.SYN && !tcp.ACK {
			s.connTracker.Store(connID, &ConnTrack{
				lastSeen:    time.Now(),
				needsBypass: true,
			})
			return true
		}
	}

	if track, ok := s.connTracker.Load(connID); ok {
		ct := track.(*ConnTrack)
		ct.lastSeen = time.Now()
		return ct.needsBypass
	}

	return false
}

func (s *Service) cleanupConnections() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupFreq) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		s.connTracker.Range(func(key, value interface{}) bool {
			ct := value.(*ConnTrack)
			if now.Sub(ct.lastSeen) > 30*time.Second {
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

func tcpFlagsString(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "SYN "
	}
	if tcp.ACK {
		flags += "ACK "
	}
	if tcp.FIN {
		flags += "FIN "
	}
	if tcp.RST {
		flags += "RST "
	}
	if tcp.PSH {
		flags += "PSH "
	}
	return flags
}

func (s *Service) createFragment(ip *layers.IPv4, tcp *layers.TCP, payload []byte) []byte {
	newTCP := *tcp
	newTCP.SetNetworkLayerForChecksum(ip)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buffer, opts,
		ip,
		&newTCP,
		gopacket.Payload(payload),
	)
	if err != nil {
		s.logger.Error("Failed to serialize fragment", zap.Error(err))
		return nil
	}

	return buffer.Bytes()
}

func (s *Service) sendImprovedFragments(ip *layers.IPv4, tcp *layers.TCP) error {
	payload := tcp.Payload
	windowSize := 5

	if err := s.sendFragment(ip, tcp, payload[:windowSize]); err != nil {
		return err
	}
	time.Sleep(time.Millisecond)

	for i := windowSize; i < len(payload); i += windowSize {
		end := i + windowSize
		if end > len(payload) {
			end = len(payload)
		}

		if err := s.sendFragment(ip, tcp, payload[i:end]); err != nil {
			return err
		}
		time.Sleep(time.Microsecond * 500)
	}

	return nil
}
