package helper

import (
    "encoding/binary"
    "fmt"
)

// TCPHdr represents a TCP header, including flag and control bit parsing.
// It enables direct manipulation of header fields like SYN, ACK, and FIN flags.
type TCPHdr struct {
    SrcPort        uint16 // Source port
    DstPort        uint16 // Destination port
    SeqNum         uint32 // Sequence number
    AckNum         uint32 // Acknowledgment number
    HdrLenAndFlags uint16 // Data offset, flags, and reserved fields packed in one word
    Window         uint16 // Window size
    Checksum       uint16 // Checksum for error-checking
    UrgPtr         uint16 // Urgent pointer (used if URG flag is set)
}

// ParseTCPHdrBytes converts a 20-byte slice into a TCPHdr structure.
// Returns an error if the data slice is too short.
func ParseTCPHdrBytes(packetBytes []byte) (*TCPHdr, error) {
    const tcpMinHdrLen = 20
    if len(packetBytes) < tcpMinHdrLen {
        return nil, fmt.Errorf("not enough bytes for TCP header: expected %d, got %d", tcpMinHdrLen, len(packetBytes))
    }
    return &TCPHdr{
        SrcPort:        binary.BigEndian.Uint16(packetBytes[0:2]),
        DstPort:        binary.BigEndian.Uint16(packetBytes[2:4]),
        SeqNum:         binary.BigEndian.Uint32(packetBytes[4:8]),
        AckNum:         binary.BigEndian.Uint32(packetBytes[8:12]),
        HdrLenAndFlags: binary.BigEndian.Uint16(packetBytes[12:14]),
        Window:         binary.BigEndian.Uint16(packetBytes[14:16]),
        Checksum:       binary.BigEndian.Uint16(packetBytes[16:18]),
        UrgPtr:         binary.BigEndian.Uint16(packetBytes[18:20]),
    }, nil
}

// ToBytes serializes the TCPHdr into a 20-byte slice in big-endian network byte order.
func (h *TCPHdr) ToBytes() []byte {
    buf := make([]byte, 20)
    binary.BigEndian.PutUint16(buf[0:2], h.SrcPort)
    binary.BigEndian.PutUint16(buf[2:4], h.DstPort)
    binary.BigEndian.PutUint32(buf[4:8], h.SeqNum)
    binary.BigEndian.PutUint32(buf[8:12], h.AckNum)
    binary.BigEndian.PutUint16(buf[12:14], h.HdrLenAndFlags)
    binary.BigEndian.PutUint16(buf[14:16], h.Window)
    binary.BigEndian.PutUint16(buf[16:18], h.Checksum)
    binary.BigEndian.PutUint16(buf[18:20], h.UrgPtr)
    return buf
}