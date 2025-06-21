package helper

import (
	"encoding/binary"
	"fmt"
)

// ICMPv6Hdr represents the ICMPv6 header structure, compatible with WINDIVERT_ICMPV6HDR.
// It includes the Type, Code, Checksum, and Body fields, where Body is typically used
// for identifiers and sequence numbers in echo requests or similar message types.
type ICMPv6Hdr struct {
	Type     uint8  // Type specifies the ICMPv6 message type.
	Code     uint8  // Code provides context for the message type.
	Checksum uint16 // Checksum is used to verify data integrity.
	Body     uint32 // Body holds additional ICMPv6 data, depending on message type.
}

// ParseICMPv6HdrBytes parses a raw byte slice into an ICMPv6Hdr.
// Returns an error if the slice is too short to represent a complete ICMPv6 header.
func ParseICMPv6HdrBytes(packetBytes []byte) (*ICMPv6Hdr, error) {
	const icmpv6HdrLen = 8
	if len(packetBytes) < icmpv6HdrLen {
		return nil, fmt.Errorf("not enough bytes for ICMPv6 header: expected %d, got %d", icmpv6HdrLen, len(packetBytes))
	}

	hdr := &ICMPv6Hdr{
		Type:     packetBytes[0],
		Code:     packetBytes[1],
		Checksum: binary.BigEndian.Uint16(packetBytes[2:4]),
		Body:     binary.BigEndian.Uint32(packetBytes[4:8]),
	}
	return hdr, nil
}

// ToBytes serializes the ICMPv6Hdr into an 8-byte slice in network byte order (big-endian).
func (h *ICMPv6Hdr) ToBytes() []byte {
	buf := make([]byte, 8)
	buf[0] = h.Type
	buf[1] = h.Code
	binary.BigEndian.PutUint16(buf[2:4], h.Checksum)
	binary.BigEndian.PutUint32(buf[4:8], h.Body)

	return buf
}
