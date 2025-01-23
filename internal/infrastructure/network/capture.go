package network

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketCapture struct {
	handle *pcap.Handle
	iface  string
}

func NewPacketCapture(iface string) (*PacketCapture, error) {
	filter := "tcp and (tcp[tcpflags] & (tcp-syn|tcp-push) != 0)"

	// Use higher snaplen and promiscuous mode
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("error opening interface: %w", err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("error setting BPF filter: %w", err)
	}

	return &PacketCapture{
		handle: handle,
		iface:  iface,
	}, nil
}

func setKernelBufferSize(handle *pcap.Handle) error {
	return nil
}

func (pc *PacketCapture) Start(callback func(packet gopacket.Packet)) error {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())

	for packet := range packetSource.Packets() {
		callback(packet)
	}

	return nil
}

func (pc *PacketCapture) Close() {
	if pc.handle != nil {
		pc.handle.Close()
	}
}

func (pc *PacketCapture) SendPacket(packet []byte) error {
	return pc.handle.WritePacketData(packet)
}

func FragmentPacket(packet gopacket.Packet, fragmentSize int) [][]byte {
	var fragments [][]byte

	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ipv4Layer == nil {
		return [][]byte{packet.Data()}
	}

	ipv4 := ipv4Layer.(*layers.IPv4)
	payload := ipv4.Payload

	maxSize := fragmentSize * 8
	numFragments := (len(payload) + maxSize - 1) / maxSize

	for i := 0; i < numFragments; i++ {
		start := i * maxSize
		end := start + maxSize
		if end > len(payload) {
			end = len(payload)
		}

		fragIPv4 := *ipv4
		fragIPv4.Length = uint16(20 + end - start)
		fragIPv4.Flags = layers.IPv4DontFragment
		if i < numFragments-1 {
			fragIPv4.Flags |= layers.IPv4MoreFragments
		}
		fragIPv4.FragOffset = uint16(i * maxSize / 8)

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		err := gopacket.SerializeLayers(buf, opts,
			&fragIPv4,
			gopacket.Payload(payload[start:end]),
		)
		if err != nil {
			continue
		}

		fragments = append(fragments, buf.Bytes())
	}

	return fragments
}

func (pc *PacketCapture) SendFragmentedPacket(packet gopacket.Packet, fragmentSize int) error {
	fragments := FragmentPacket(packet, fragmentSize)
	for _, fragment := range fragments {
		if err := pc.SendPacket(fragment); err != nil {
			return err
		}
	}
	return nil
}
