package helper

import (
    "encoding/binary"
    "fmt"
)

// UDPHdr represents a UDP header, including fields for source/destination ports,
// datagram length, and checksum.
type UDPHdr struct {
    SrcPort  uint16 // Source port number
    DstPort  uint16 // Destination port number
    Length   uint16 // Length of UDP header + payload
    Checksum uint16 // UDP checksum
}

// ParseUDPHdrBytes parses an 8-byte slice into a UDPHdr.
// Returns an error if the data slice is too short for a complete UDP header.
func ParseUDPHdrBytes(packetBytes []byte) (*UDPHdr, error) {
    const udpHdrLen = 8
    if len(packetBytes) < udpHdrLen {
        return nil, fmt.Errorf("not enough bytes for UDP header: expected %d, got %d", udpHdrLen, len(packetBytes))
    }
    return &UDPHdr{
        SrcPort:  binary.BigEndian.Uint16(packetBytes[0:2]),
        DstPort:  binary.BigEndian.Uint16(packetBytes[2:4]),
        Length:   binary.BigEndian.Uint16(packetBytes[4:6]),
        Checksum: binary.BigEndian.Uint16(packetBytes[6:8]),
    }, nil
}

// ToBytes serializes the UDPHdr into an 8-byte slice in network byte order.
func (h *UDPHdr) ToBytes() []byte {
    buf := make([]byte, 8)
    binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
    binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
    binary.BigEndian.PutUint16(buf[4:6], h.Length)
    binary.BigEndian.PutUint16(buf[6:8], h.Checksum)
    return buf
}
