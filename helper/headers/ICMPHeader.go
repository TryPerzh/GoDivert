package helper

import (
	"encoding/binary"
	"fmt"
)

// ICMPHdr represents the structure of an ICMP header, compatible with WINDIVERT_ICMPHDR.
type ICMPHdr struct {
	Type     uint8  // Type specifies the ICMP message type.
	Code     uint8  // Code provides further information about the type.
	Checksum uint16 // Checksum is used for error-checking the header.
	Body     uint32 // Body holds additional data (like Identifier and Sequence Number in echo requests).
}

// ParseICMPHdrBytes parses a raw byte slice into an ICMPHdr structure.
// Returns an error if the provided slice is too short to contain a full ICMP header.
func ParseICMPHdrBytes(packetBytes []byte) (*ICMPHdr, error) {
	const icmpHdrLen = 8
	if len(packetBytes) < icmpHdrLen {
		return nil, fmt.Errorf("not enough bytes for ICMP header: expected %d, got %d", icmpHdrLen, len(packetBytes))
	}

	hdr := &ICMPHdr{
		Type:     packetBytes[0],
		Code:     packetBytes[1],
		Checksum: binary.BigEndian.Uint16(packetBytes[2:4]),
		Body:     binary.BigEndian.Uint32(packetBytes[4:8]),
	}
	return hdr, nil
}

// ToBytes serializes the ICMPHdr structure into a byte slice in big-endian order.
// Returns an 8-byte slice representing the ICMP header.
func (h *ICMPHdr) ToBytes() []byte {
	buf := make([]byte, 8)
	buf[0] = h.Type
	buf[1] = h.Code
	binary.BigEndian.PutUint16(buf[2:4], h.Checksum)
	binary.BigEndian.PutUint32(buf[4:8], h.Body)

	return buf
}
