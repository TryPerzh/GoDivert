package helper

/*
#cgo windows CFLAGS: -I${SRCDIR}/../WinDivert
#cgo windows LDFLAGS: -L${SRCDIR}/../WinDivert -lWinDivert -lws2_32
#include "windivert.h"
*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	h "gitlab.com/perozh/GoDivert/helper/headers"
)

func lastError() error {
	code := C.GetLastError()

	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("error code %d", code)
	}
	callerFunc := runtime.FuncForPC(pc).Name()
	parts := strings.Split(callerFunc, ".")
	simpleFuncName := parts[len(parts)-1] // Get the last part (function name)

	return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)

}

// HelperFlag represents flags used by WinDivert helper functions for checksum calculation.
// These flags control which checksums should be automatically calculated or skipped
// when processing packets with helper functions.
type HelperFlag uint64

const (
	// HelperNoIpChecksum indicates that IP header checksums should not be calculated.
	// When this flag is set, the IP checksum field will be left unchanged.
	// Useful when working with packets that already have correct IP checksums.
	HelperNoIpChecksum HelperFlag = 1

	// HelperNoIcmpChecksum indicates that ICMP header checksums should not be calculated.
	// When this flag is set, the ICMP checksum field will be left unchanged.
	// Applies to ICMPv4 packets only.
	HelperNoIcmpChecksum HelperFlag = 2

	// HelperNoIcmpv6Checksum indicates that ICMPv6 header checksums should not be calculated.
	// When this flag is set, the ICMPv6 checksum field will be left unchanged.
	// Applies to ICMPv6 packets only.
	HelperNoIcmpv6Checksum HelperFlag = 4

	// HelperNoTcpChecksum indicates that TCP header checksums should not be calculated.
	// When this flag is set, the TCP checksum field will be left unchanged.
	// Useful when the TCP stack will handle checksum calculation.
	HelperNoTcpChecksum HelperFlag = 8

	// HelperNoUdpChecksum indicates that UDP header checksums should not be calculated.
	// When this flag is set, the UDP checksum field will be left unchanged.
	// Note that UDP checksums are mandatory for IPv6 but optional for IPv4.
	HelperNoUdpChecksum HelperFlag = 16
)

// WinDivertParseResult contains parsed headers of a packet.
type WinDivertParseResult struct {
	IpHdr      *h.IPHdr     // Parsed IPv4 header
	Ipv6Hdr    *h.IPv6Hdr   // Parsed IPv6 header
	Protocol   uint8        // Protocol of the next header (e.g., 6 for TCP, 17 for UDP)
	IcmpHdr    *h.ICMPHdr   // Parsed ICMP header
	Icmpv6Hdr  *h.ICMPv6Hdr // Parsed ICMPv6 header
	TcpHdr     *h.TCPHdr    // Parsed TCP header
	UdpHdr     *h.UDPHdr    // Parsed UDP header
	Data       []byte       // Payload data of the packet
	DataLen    uint         // Length of the payload data
	NextHeader []byte       // Next unrecognized header or its start
	NextLen    uint         // Length of the next unrecognized header
}

// ParsePacket wraps the C function WinDivertHelperParsePacket to parse a packet.
// It takes a byte slice representing the packet data and returns a WinDivertParseResult
// containing parsed headers and payload data. An error is returned if parsing fails.
func ParsePacket(packet []byte) (*WinDivertParseResult, error) {
	if len(packet) == 0 {
		return nil, fmt.Errorf("packet cannot be empty")
	}

	var cIpHdr unsafe.Pointer
	var cIpv6Hdr unsafe.Pointer
	var cProtocol C.UINT8
	var cIcmpHdr unsafe.Pointer
	var cIcmpv6Hdr unsafe.Pointer
	var cTcpHdr unsafe.Pointer
	var cUdpHdr unsafe.Pointer
	var cData unsafe.Pointer // Already *unsafe.Pointer
	var cDataLen C.UINT
	var cNext unsafe.Pointer // Already *unsafe.Pointer
	var cNextLen C.UINT

	// Convert Go slice to C pointer for pPacket
	cPacketPtr := unsafe.Pointer(&packet[0])

	b := C.WinDivertHelperParsePacket(
		cPacketPtr,
		C.UINT(len(packet)),
		(*C.PWINDIVERT_IPHDR)(unsafe.Pointer(&cIpHdr)),
		(*C.PWINDIVERT_IPV6HDR)(unsafe.Pointer(&cIpv6Hdr)),
		&cProtocol,
		(*C.PWINDIVERT_ICMPHDR)(unsafe.Pointer(&cIcmpHdr)),
		(*C.PWINDIVERT_ICMPV6HDR)(unsafe.Pointer(&cIcmpv6Hdr)),
		(*C.PWINDIVERT_TCPHDR)(unsafe.Pointer(&cTcpHdr)),
		(*C.PWINDIVERT_UDPHDR)(unsafe.Pointer(&cUdpHdr)),
		(*C.PVOID)(unsafe.Pointer(&cData)),
		&cDataLen,
		(*C.PVOID)(unsafe.Pointer(&cNext)),
		&cNextLen,
	)

	if b == 0 {
		return nil, lastError()
	}

	result := &WinDivertParseResult{}

	packetBase := uintptr(cPacketPtr)

	if cIpHdr != nil {
		offset := uintptr(unsafe.Pointer(cIpHdr)) - packetBase
		if offset < uintptr(len(packet)) { // Boundary check
			result.IpHdr = &h.IPHdr{}
			parsedIPHdr, err := h.ParseIPHdrBytes(packet[offset:])
			if err == nil {
				result.IpHdr = parsedIPHdr
			} else {
				fmt.Printf("IPHdr parsing error: %v\n", err)
				result.IpHdr = nil
			}
		}
	}

	if cIpv6Hdr != nil {
		offset := uintptr(unsafe.Pointer(cIpv6Hdr)) - packetBase
		if offset < uintptr(len(packet)) {
			result.Ipv6Hdr = &h.IPv6Hdr{}
			parsedIPv6Hdr, err := h.ParseIPv6HdrBytes(packet[offset:])
			if err == nil {
				result.Ipv6Hdr = parsedIPv6Hdr
			} else {
				fmt.Printf("IPv6Hdr parsing error: %v\n", err)
				result.Ipv6Hdr = nil
			}
		}
	}

	result.Protocol = uint8(cProtocol)

	if cIcmpHdr != nil {
		offset := uintptr(unsafe.Pointer(cIcmpHdr)) - packetBase
		if offset < uintptr(len(packet)) {
			result.IcmpHdr = &h.ICMPHdr{}
			parsedICMPHdr, err := h.ParseICMPHdrBytes(packet[offset:])
			if err == nil {
				result.IcmpHdr = parsedICMPHdr
			} else {
				fmt.Printf("ICMPHdr parsing error: %v\n", err)
				result.IcmpHdr = nil
			}
		}
	}

	if cIcmpv6Hdr != nil {
		offset := uintptr(unsafe.Pointer(cIcmpv6Hdr)) - packetBase
		if offset < uintptr(len(packet)) {
			result.Icmpv6Hdr = &h.ICMPv6Hdr{}
			parsedICMPv6Hdr, err := h.ParseICMPv6HdrBytes(packet[offset:])
			if err == nil {
				result.Icmpv6Hdr = parsedICMPv6Hdr
			} else {
				fmt.Printf("ICMPv6Hdr parsing error: %v\n", err)
				result.Icmpv6Hdr = nil
			}
		}
	}

	if cTcpHdr != nil {
		offset := uintptr(unsafe.Pointer(cTcpHdr)) - packetBase
		if offset < uintptr(len(packet)) {
			result.TcpHdr = &h.TCPHdr{}
			parsedTCPHdr, err := h.ParseTCPHdrBytes(packet[offset:])
			if err == nil {
				result.TcpHdr = parsedTCPHdr
			} else {
				fmt.Printf("TCPHdr parsing error: %v\n", err)
				result.TcpHdr = nil
			}
		}
	}

	if cUdpHdr != nil {
		offset := uintptr(unsafe.Pointer(cUdpHdr)) - packetBase
		if offset < uintptr(len(packet)) {
			result.UdpHdr = &h.UDPHdr{}
			parsedUDPHdr, err := h.ParseUDPHdrBytes(packet[offset:])
			if err == nil {
				result.UdpHdr = parsedUDPHdr
			} else {
				fmt.Printf("UDPHdr parsing error: %v\n", err)
				result.UdpHdr = nil
			}
		}
	}

	if cData != nil && cDataLen > 0 {
		offset := uintptr(cData) - packetBase
		if offset < uintptr(len(packet)) {
			endOffset := offset + uintptr(cDataLen)
			if endOffset > uintptr(len(packet)) {
				endOffset = uintptr(len(packet))
			}
			result.Data = make([]byte, endOffset-offset)
			copy(result.Data, packet[offset:endOffset])
			result.DataLen = uint(endOffset - offset)
		}
	}

	if cNext != nil && cNextLen > 0 {
		offset := uintptr(cNext) - packetBase
		if offset < uintptr(len(packet)) {
			endOffset := offset + uintptr(cNextLen)
			if endOffset > uintptr(len(packet)) {
				endOffset = uintptr(len(packet))
			}
			result.NextHeader = make([]byte, endOffset-offset)
			copy(result.NextHeader, packet[offset:endOffset])
			result.NextLen = uint(endOffset - offset)
		}
	}

	return result, nil
}

// HashPacket computes a hash of the given packet using the WinDivertHelperHashPacket C function.
// It takes a byte slice of the packet data and a seed for the hash function.
// It returns a uint64 hash value or an error if hashing fails.
func HashPacket(packet []byte, seed uint64) (uint64, error) {
	if len(packet) == 0 {
		return 0, nil
	}

	cPacketPtr := unsafe.Pointer(&packet[0])

	hash := C.WinDivertHelperHashPacket(
		cPacketPtr,
		C.UINT(len(packet)),
		C.UINT64(seed),
	)

	// WinDivertHelperHashPacket returns 0 if an error occurred.
	// Because 0 can also be a valid hash, use GetLastError() to check for errors.
	if hash == 0 && len(packet) > 0 {
		if err := lastError(); err != nil {
			return 0, fmt.Errorf("WinDivertHelperHashPacket error: %v", err)
		}
	}

	return uint64(hash), nil
}

// ParseIPv4Address parses an IPv4 address string into a uint32 representation.
// It returns the parsed address or an error if parsing fails.
func ParseIPv4Address(addrStr string) (uint32, error) {
	cAddrStr := C.CString(addrStr)
	defer C.free(unsafe.Pointer(cAddrStr))

	var cAddr C.UINT32

	b := C.WinDivertHelperParseIPv4Address(
		cAddrStr,
		&cAddr,
	)

	if b == 0 {
		return 0, fmt.Errorf("error parsing IPv4 address '%s': %v", addrStr, lastError())
	}

	return uint32(cAddr), nil
}

// ParseIPv6Address parses an IPv6 address string into a uint32 representation.
// It returns the parsed address or an error if parsing fails.
func ParseIPv6Address(addrStr string) (uint32, error) {
	cAddrStr := C.CString(addrStr)
	defer C.free(unsafe.Pointer(cAddrStr))

	var cAddr C.UINT32

	b := C.WinDivertHelperParseIPv6Address(
		cAddrStr,
		&cAddr,
	)

	if b == 0 {
		return 0, fmt.Errorf("error parsing IPv6 address '%s': %v", addrStr, lastError())
	}

	return uint32(cAddr), nil
}

// FormatIPv4Address formats a uint32 IP address into a string representation.
// It returns the formatted IP address string or an error if formatting fails.
func FormatIPv4Address(addr uint32) (string, error) {
	const bufferSize = 20 // Enough space for IP + null terminator

	buffer := make([]byte, bufferSize)
	cBufferPtr := (*C.char)(unsafe.Pointer(&buffer[0]))
	cBufLen := C.UINT(len(buffer))

	b := C.WinDivertHelperFormatIPv4Address(
		C.UINT32(addr),
		cBufferPtr,
		cBufLen,
	)

	if b == 0 {
		return "", fmt.Errorf("error formatting IPv4 address '%d': %v", addr, lastError())
	}

	return string(buffer[:cBufLen]), nil
}

// FormatIPv6Address formats a IPv6 address given as an array of uint32 into a string representation.
// It returns the formatted IPv6 address string or an error if formatting fails.
func FormatIPv6Address(addr [4]uint32) (string, error) {
	const bufferSize = 65 // Enough space for IPv6 + null terminator

	buffer := make([]byte, bufferSize)
	cBufferPtr := (*C.char)(unsafe.Pointer(&buffer[0]))
	cBufLen := C.UINT(len(buffer))

	// WinDivertHelperFormatIPv6Address expects const UINT32 *pAddr
	// We have a Go array of [4]uint32. We need to pass a pointer to the first element.
	cAddrPtr := (*C.UINT32)(unsafe.Pointer(&addr[0]))

	b := C.WinDivertHelperFormatIPv6Address(
		cAddrPtr,
		cBufferPtr,
		cBufLen,
	)

	if b == 0 {
		return "", fmt.Errorf("error formatting IPv6 address: %v", lastError())
	}

	return string(buffer[:cBufLen]), nil
}

// CalcChecksums calculates checksums for the given packet using WinDivertHelperCalcChecksums.
// It takes a byte slice of the packet data, a pointer to a WINDIVERT_ADDRESS structure,
// and flags for checksum calculation. It returns true if successful, or an error.
func CalcChecksums(packet []byte, addr *C.WINDIVERT_ADDRESS, flags HelperFlag) (bool, error) {
	if len(packet) == 0 {
		return false, fmt.Errorf("packet cannot be empty")
	}

	b := C.WinDivertHelperCalcChecksums(
		unsafe.Pointer(&packet[0]),
		C.UINT(len(packet)),
		addr,
		C.UINT64(flags),
	)

	if b == 0 {
		return false, fmt.Errorf("WinDivertHelperCalcChecksums error: %v", lastError())
	}

	return true, nil
}

// Ntohs converts a uint16 from network to host byte order.
// It returns the converted value.
func Ntohs(x uint16) uint16 {
	return uint16(C.WinDivertHelperNtohs(C.UINT16(x)))
}

// Htons converts a uint16 from host to network byte order.
// It returns the converted value.
func Htons(x uint16) uint16 {
	return uint16(C.WinDivertHelperHtons(C.UINT16(x)))
}

// Ntohl converts a uint32 from network to host byte order.
// It returns the converted value.
func Ntohl(x uint32) uint32 {
	return uint32(C.WinDivertHelperNtohl(C.UINT32(x)))
}

// Htonl converts a uint32 from host to network byte order.
// It returns the converted value.
func Htonl(x uint32) uint32 {
	return uint32(C.WinDivertHelperHtonl(C.UINT32(x)))
}

// Ntohll converts a uint64 from network to host byte order.
// It returns the converted value.
func Ntohll(x uint64) uint64 {
	return uint64(C.WinDivertHelperNtohll(C.UINT64(x)))
}

// Htonll converts a uint64 from host to network byte order.
// It returns the converted value.
func Htonll(x uint64) uint64 {
	return uint64(C.WinDivertHelperHtonll(C.UINT64(x)))
}

// NtohIPv6Address converts an IPv6 address from network to host byte order.
// It returns the converted IPv6 address.
func NtohIPv6Address(inAddr [4]uint32) [4]uint32 {
	var outAddr [4]uint32

	cInAddrPtr := (*C.UINT)(unsafe.Pointer(&inAddr[0]))
	cOutAddrPtr := (*C.UINT)(unsafe.Pointer(&outAddr[0]))

	C.WinDivertHelperNtohIPv6Address(cInAddrPtr, cOutAddrPtr)

	return outAddr
}

// HtonIPv6Address converts an IPv6 address from host to network byte order.
// It returns the converted IPv6 address.
func HtonIPv6Address(inAddr [4]uint32) [4]uint32 {
	var outAddr [4]uint32

	cInAddrPtr := (*C.UINT)(unsafe.Pointer(&inAddr[0]))
	cOutAddrPtr := (*C.UINT)(unsafe.Pointer(&outAddr[0]))

	C.WinDivertHelperHtonIPv6Address(cInAddrPtr, cOutAddrPtr)

	return outAddr
}

// Uint32IpToBytes converts a uint32 IP address into a byte slice.
// It returns the byte representation of the IP address.
func Uint32IpToBytes(ipUint32 uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, ipUint32)
	return buf
}
