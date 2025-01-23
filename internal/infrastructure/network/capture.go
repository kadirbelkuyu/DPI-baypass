package network

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

type PacketCapture struct {
	handle *pcap.Handle
}

func NewPacketCapture(interfaceName string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(
		interfaceName,
		65535, // Max buffer size
		true,  // Promiscuous mode
		pcap.BlockForever,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface: %v", err)
	}

	if err := handle.SetBPFFilter("tcp and (port 80 or port 443)"); err != nil {
		return nil, fmt.Errorf("BPF filter error: %v", err)
	}

	return &PacketCapture{handle: handle}, nil
}

func (pc *PacketCapture) Start(handler func(gopacket.Packet)) error {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	for packet := range packetSource.Packets() {
		handler(packet)
	}
	return nil
}

func (pc *PacketCapture) SendPacket(data []byte) error {
	for i := 0; i < 3; i++ { // Retry 3 times
		if err := pc.handle.WritePacketData(data); err == nil {
			return nil
		}
		time.Sleep(10 * time.Microsecond)
	}
	return fmt.Errorf("failed to send packet after 3 attempts")
}

func (pc *PacketCapture) Close() {
	pc.handle.Close()
}
