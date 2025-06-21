package helper

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPHdr represents the structure of an IPv4 header, aligned with WINDIVERT_IPHDR.
// It includes utility methods to access and modify header length, version,
// fragmentation flags, and IP addresses.
type IPHdr struct {
	VersionAndHdrLength uint8  // 4 bits version and 4 bits header length
	TOS                 uint8  // Type of service
	Length              uint16 // Total packet length
	Id                  uint16 // Identification field
	FragOff0            uint16 // Fragment offset and flags (13 bits offset + 3 bits flags)
	TTL                 uint8  // Time to live
	Protocol            uint8  // Protocol type (e.g., TCP, UDP)
	Checksum            uint16 // Header checksum
	SrcAddr             net.IP // Source IPv4 address
	DstAddr             net.IP // Destination IPv4 address
}

// ParseIPHdrBytes parses a raw byte slice into an IPHdr.
// Returns an error if the slice is shorter than the minimum IPv4 header size (20 bytes).
func ParseIPHdrBytes(packetBytes []byte) (*IPHdr, error) {
	const ipHdrLen = 20
	if len(packetBytes) < ipHdrLen {
		return nil, fmt.Errorf("not enough bytes for IP header: expected %d, got %d", ipHdrLen, len(packetBytes))
	}
	hdr := &IPHdr{
		VersionAndHdrLength: packetBytes[0],
		TOS:                 packetBytes[1],
		Length:              binary.BigEndian.Uint16(packetBytes[2:4]),
		Id:                  binary.BigEndian.Uint16(packetBytes[4:6]),
		FragOff0:            binary.BigEndian.Uint16(packetBytes[6:8]),
		TTL:                 packetBytes[8],
		Protocol:            packetBytes[9],
		Checksum:            binary.BigEndian.Uint16(packetBytes[10:12]),
		SrcAddr:             uint32ToIPv4(binary.BigEndian.Uint32(packetBytes[12:16])),
		DstAddr:             uint32ToIPv4(binary.BigEndian.Uint32(packetBytes[16:20])),
	}
	return hdr, nil
}

// ToBytes serializes the IPHdr into a 20-byte slice in network byte order (big-endian).
func (h *IPHdr) ToBytes() []byte {
	buf := make([]byte, 20)
	buf[0] = h.VersionAndHdrLength
	buf[1] = h.TOS
	binary.BigEndian.PutUint16(buf[2:4], h.Length)
	binary.BigEndian.PutUint16(buf[4:6], h.Id)
	binary.BigEndian.PutUint16(buf[6:8], h.FragOff0)
	buf[8] = h.TTL
	buf[9] = h.Protocol
	binary.BigEndian.PutUint16(buf[10:12], h.Checksum)
	binary.BigEndian.PutUint32(buf[12:16], iPv4ToUint32(h.SrcAddr))
	binary.BigEndian.PutUint32(buf[16:20], iPv4ToUint32(h.DstAddr))
	return buf
}

// uint32ToIPv4 converts uint32 to net.IP (для IPv4)
func uint32ToIPv4(ipUint uint32) net.IP {
	// net.IP для IPv4 є слайсом байтів довжиною 4
	ip := make(net.IP, 4)
	ip[0] = byte((ipUint >> 24) & 0xFF) // Найстарший байт
	ip[1] = byte((ipUint >> 16) & 0xFF)
	ip[2] = byte((ipUint >> 8) & 0xFF)
	ip[3] = byte(ipUint & 0xFF) // Найменший байт
	return ip
}

func iPv4ToUint32(ip net.IP) uint32 {

	ipv4 := ip.To4()
	if ipv4 == nil {
		return 0
	}

	return binary.BigEndian.Uint32(ipv4)
}
