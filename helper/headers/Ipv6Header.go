package helper

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPv6Hdr represents the WINDIVERT_IPV6HDR structure with support for parsing
// and serializing IPv6 packet headers. It provides methods for accessing version,
// traffic class, flow label, and IP address fields.
type IPv6Hdr struct {
	VersionAndTrafficClass0    uint8  // Higher 4 bits: Version, Lower 4 bits: Traffic Class (high nibble)
	TrafficClass1AndFlowLabel0 uint8  // Higher 4 bits: Traffic Class (low nibble), Lower 4 bits: Flow Label (high nibble)
	FlowLabel1                 uint16 // Lower 16 bits of Flow Label
	Length                     uint16 // Payload length (excluding the IPv6 header)
	NextHdr                    uint8  // Next header protocol (e.g., TCP, UDP, ICMPv6)
	HopLimit                   uint8  // Hop limit (similar to TTL in IPv4)
	SrcAddr                    net.IP // Source IPv6 address (128 bits, represented as 16 bytes in net.IP)
	DstAddr                    net.IP // Destination IPv6 address (128 bits, represented as 16 bytes in net.IP)
}

// ParseIPv6HdrBytes parses a 40-byte slice into an IPv6Hdr structure.
// Returns an error if the slice is too short.
func ParseIPv6HdrBytes(packetBytes []byte) (*IPv6Hdr, error) {
	const ipv6HdrLen = 40
	if len(packetBytes) < ipv6HdrLen {
		return nil, fmt.Errorf("not enough bytes for IPv6 header: expected %d, got %d", ipv6HdrLen, len(packetBytes))
	}
	hdr := &IPv6Hdr{
		VersionAndTrafficClass0:    packetBytes[0],
		TrafficClass1AndFlowLabel0: packetBytes[1],
		FlowLabel1:                 binary.BigEndian.Uint16(packetBytes[2:4]),
		Length:                     binary.BigEndian.Uint16(packetBytes[4:6]),
		NextHdr:                    packetBytes[6],
		HopLimit:                   packetBytes[7],
	}

	hdr.SrcAddr = net.IP(append([]byte{}, packetBytes[8:24]...))
	hdr.DstAddr = net.IP(append([]byte{}, packetBytes[24:40]...))

	return hdr, nil
}

// ToBytes serializes the IPv6Hdr back into a 40-byte slice in network byte order.
func (h *IPv6Hdr) ToBytes() []byte {
	buf := make([]byte, 40)
	buf[0] = h.VersionAndTrafficClass0
	buf[1] = h.TrafficClass1AndFlowLabel0
	binary.BigEndian.PutUint16(buf[2:4], h.FlowLabel1)
	binary.BigEndian.PutUint16(buf[4:6], h.Length)
	buf[6] = h.NextHdr
	buf[7] = h.HopLimit

	copy(buf[8:24], h.SrcAddr.To16())  // Копіюємо 16 байтів Source IP
	copy(buf[24:40], h.DstAddr.To16()) // Копіюємо 16 байтів Destination IP

	return buf
}
