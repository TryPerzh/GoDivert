package GoDivert

/*
#cgo windows CFLAGS: -I${SRCDIR}/WinDivert
#cgo windows LDFLAGS: -L${SRCDIR}/WinDivert -lWinDivert -lws2_32
#include "windivert.h"
#include <string.h>

uint32_t get_layer(WINDIVERT_ADDRESS* addr) {
    return addr->Layer;
}

void set_layer(WINDIVERT_ADDRESS* addr, uint32_t layer) {
    addr->Layer = layer;
}

uint32_t get_event(WINDIVERT_ADDRESS* addr) {
    return addr->Event;
}

void set_event(WINDIVERT_ADDRESS* addr, uint32_t event) {
    addr->Event = event;
}

uint32_t get_sniffed(WINDIVERT_ADDRESS* addr) {
    return addr->Sniffed;
}

void set_sniffed(WINDIVERT_ADDRESS* addr, uint32_t sniffed) {
    addr->Sniffed = sniffed;
}

uint32_t get_outbound(WINDIVERT_ADDRESS* addr) {
    return addr->Outbound;
}

void set_outbound(WINDIVERT_ADDRESS* addr, uint32_t outbound) {
    addr->Outbound = outbound;
}

uint32_t get_loopback(WINDIVERT_ADDRESS* addr) {
    return addr->Loopback;
}

void set_loopback(WINDIVERT_ADDRESS* addr, uint32_t loopback) {
    addr->Loopback = loopback;
}

uint32_t get_impostor(WINDIVERT_ADDRESS* addr) {
    return addr->Impostor;
}

void set_impostor(WINDIVERT_ADDRESS* addr, uint32_t impostor) {
    addr->Impostor = impostor;
}

uint32_t get_ipv6(WINDIVERT_ADDRESS* addr) {
    return addr->IPv6;
}

void set_ipv6(WINDIVERT_ADDRESS* addr, uint32_t ipv6) {
    addr->IPv6 = ipv6;
}

uint32_t get_ip_checksum(WINDIVERT_ADDRESS* addr) {
    return addr->IPChecksum;
}

void set_ip_checksum(WINDIVERT_ADDRESS* addr, uint32_t checksum) {
    addr->IPChecksum = checksum;
}

uint32_t get_tcp_checksum(WINDIVERT_ADDRESS* addr) {
    return addr->TCPChecksum;
}

void set_tcp_checksum(WINDIVERT_ADDRESS* addr, uint32_t checksum) {
    addr->TCPChecksum = checksum;
}

uint32_t get_udp_checksum(WINDIVERT_ADDRESS* addr) {
    return addr->UDPChecksum;
}

void set_udp_checksum(WINDIVERT_ADDRESS* addr, uint32_t checksum) {
    addr->UDPChecksum = checksum;
}


void get_network_data(WINDIVERT_ADDRESS* addr, uint32_t* ifIdx, uint32_t* subIfIdx) {
    *ifIdx = addr->Network.IfIdx;
    *subIfIdx = addr->Network.SubIfIdx;
}

void set_network_data(WINDIVERT_ADDRESS* addr, uint32_t ifIdx, uint32_t subIfIdx) {
    addr->Network.IfIdx = ifIdx;
    addr->Network.SubIfIdx = subIfIdx;
}


void get_flow_data(WINDIVERT_ADDRESS* addr, uint64_t* endpointId, uint64_t* parentEndpointId,
                   uint32_t* processId, uint32_t localAddr[4], uint32_t remoteAddr[4],
                   uint16_t* localPort, uint16_t* remotePort, uint8_t* protocol) {
    *endpointId = addr->Flow.EndpointId;
    *parentEndpointId = addr->Flow.ParentEndpointId;
    *processId = addr->Flow.ProcessId;
    memcpy(localAddr, addr->Flow.LocalAddr, sizeof(uint32_t) * 4);
    memcpy(remoteAddr, addr->Flow.RemoteAddr, sizeof(uint32_t) * 4);
    *localPort = addr->Flow.LocalPort;
    *remotePort = addr->Flow.RemotePort;
    *protocol = addr->Flow.Protocol;
}

void set_flow_data(WINDIVERT_ADDRESS* addr, uint64_t endpointId, uint64_t parentEndpointId,
                   uint32_t processId, uint32_t localAddr[4], uint32_t remoteAddr[4],
                   uint16_t localPort, uint16_t remotePort, uint8_t protocol) {
    addr->Flow.EndpointId = endpointId;
    addr->Flow.ParentEndpointId = parentEndpointId;
    addr->Flow.ProcessId = processId;
    memcpy(addr->Flow.LocalAddr, localAddr, sizeof(uint32_t) * 4);
    memcpy(addr->Flow.RemoteAddr, remoteAddr, sizeof(uint32_t) * 4);
    addr->Flow.LocalPort = localPort;
    addr->Flow.RemotePort = remotePort;
    addr->Flow.Protocol = protocol;
}


void get_socket_data(WINDIVERT_ADDRESS* addr, uint64_t* endpointId, uint64_t* parentEndpointId,
                     uint32_t* processId, uint32_t localAddr[4], uint32_t remoteAddr[4],
                     uint16_t* localPort, uint16_t* remotePort, uint8_t* protocol) {
    *endpointId = addr->Socket.EndpointId;
    *parentEndpointId = addr->Socket.ParentEndpointId;
    *processId = addr->Socket.ProcessId;
    memcpy(localAddr, addr->Socket.LocalAddr, sizeof(uint32_t) * 4);
    memcpy(remoteAddr, addr->Socket.RemoteAddr, sizeof(uint32_t) * 4);
    *localPort = addr->Socket.LocalPort;
    *remotePort = addr->Socket.RemotePort;
    *protocol = addr->Socket.Protocol;
}

void set_socket_data(WINDIVERT_ADDRESS* addr, uint64_t endpointId, uint64_t parentEndpointId,
                     uint32_t processId, uint32_t localAddr[4], uint32_t remoteAddr[4],
                     uint16_t localPort, uint16_t remotePort, uint8_t protocol) {
    addr->Socket.EndpointId = endpointId;
    addr->Socket.ParentEndpointId = parentEndpointId;
    addr->Socket.ProcessId = processId;
    memcpy(addr->Socket.LocalAddr, localAddr, sizeof(uint32_t) * 4);
    memcpy(addr->Socket.RemoteAddr, remoteAddr, sizeof(uint32_t) * 4);
    addr->Socket.LocalPort = localPort;
    addr->Socket.RemotePort = remotePort;
    addr->Socket.Protocol = protocol;
}


void get_reflect_data(WINDIVERT_ADDRESS* addr, int64_t* timestamp, uint32_t* processId,
                      uint32_t* layer, uint64_t* flags, int16_t* priority) {
    *timestamp = addr->Reflect.Timestamp;
    *processId = addr->Reflect.ProcessId;
    *layer = (uint32_t)addr->Reflect.Layer;
    *flags = addr->Reflect.Flags;
    *priority = addr->Reflect.Priority;
}

void set_reflect_data(WINDIVERT_ADDRESS* addr, int64_t timestamp, uint32_t processId,
                      uint32_t layer, uint64_t flags, int16_t priority) {
    addr->Reflect.Timestamp = timestamp;
    addr->Reflect.ProcessId = processId;
    addr->Reflect.Layer = (WINDIVERT_LAYER)layer;
    addr->Reflect.Flags = flags;
    addr->Reflect.Priority = priority;
}


void init_windivert_address(WINDIVERT_ADDRESS* addr) {
    memset(addr, 0, sizeof(WINDIVERT_ADDRESS));
}
*/
import "C"
import (
	"net"
)

// DataNetwork contains network layer specific information for intercepted packets.
// This structure is used when packets are captured at the Network layer.
type NetworkData struct {
	IfIdx    uint32
	SubIfIdx uint32
}

// DataFlow contains flow-specific information for network connections.
// This structure is used when flows are captured at the Flow layer.
// A flow represents a sequence of related packets (e.g., TCP connection).
type FlowData struct {
	EndpointId       uint64
	ParentEndpointId uint64
	ProcessId        uint32
	LocalAddr        net.IP
	RemoteAddr       net.IP
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
}

// DataSocket contains socket layer specific information for intercepted packets.
// This structure is used when packets are captured at the Socket layer,
// providing the earliest interception point for outbound traffic.
type SocketData struct {
	EndpointId       uint64
	ParentEndpointId uint64
	ProcessId        uint32
	LocalAddr        net.IP
	RemoteAddr       net.IP
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
}

// DataReflect contains reflection layer specific information.
// This structure is used when packets are captured at the Reflect layer,
// which is primarily used for testing and debugging WinDivert filters.
type ReflectData struct {
	Timestamp int64
	ProcessId uint32
	Layer     uint32
	Flags     uint64
	Priority  int16
}

// Address represents a WinDivert address structure. This structure contains metadata
type Address struct {
	Timestamp   int64
	Layer       uint8
	Event       uint8
	Sniffed     bool
	Outbound    bool
	Loopback    bool
	Impostor    bool
	IPv6        bool
	IPChecksum  bool
	TCPChecksum bool
	UDPChecksum bool

	// Union data - тільки один з них буде активним
	Network *NetworkData
	Flow    *FlowData
	Socket  *SocketData
	Reflect *ReflectData
}

// uint32ArrayToIP converts an array of four uint32 values into a net.IP address.
// If isIPv6 is true, it treats the array as an IPv6 address and returns a 16-byte IP.
// Otherwise, it interprets the first uint32 as an IPv4 address and returns a 4-byte IP.
func uint32ArrayToIP(addr [4]uint32, isIPv6 bool) net.IP {
	if isIPv6 {
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i*4] = byte(addr[i] >> 24)
			ip[i*4+1] = byte(addr[i] >> 16)
			ip[i*4+2] = byte(addr[i] >> 8)
			ip[i*4+3] = byte(addr[i])
		}
		return ip
	} else {
		// IPv4 - використовуємо тільки перший uint32
		return net.IPv4(
			byte(addr[0]),
			byte(addr[0]>>8),
			byte(addr[0]>>16),
			byte(addr[0]>>24),
		)
	}
}

// ipToUint32Array converts a net.IP address into an array of four uint32 values. If
// the IP address is an IPv4 address, it packs the four bytes of the address into
// the first uint32. If the IP address is an IPv6 address, it packs the 16 bytes of
// the address into the four uint32 values.
func ipToUint32Array(ip net.IP) [4]uint32 {
	var addr [4]uint32

	if ip.To4() != nil {
		// IPv4
		ip4 := ip.To4()
		addr[0] = uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24
	} else {
		// IPv6
		ip16 := ip.To16()
		for i := 0; i < 4; i++ {
			addr[i] = uint32(ip16[i*4]) | uint32(ip16[i*4+1])<<8 |
				uint32(ip16[i*4+2])<<16 | uint32(ip16[i*4+3])<<24
		}
	}

	return addr
}

func CAddressToGo(cAddr *C.WINDIVERT_ADDRESS) *Address {
	addr := &Address{
		Timestamp:   int64(cAddr.Timestamp),
		Layer:       uint8(C.get_layer(cAddr)),
		Event:       uint8(C.get_event(cAddr)),
		Sniffed:     C.get_sniffed(cAddr) != 0,
		Outbound:    C.get_outbound(cAddr) != 0,
		Loopback:    C.get_loopback(cAddr) != 0,
		Impostor:    C.get_impostor(cAddr) != 0,
		IPv6:        C.get_ipv6(cAddr) != 0,
		IPChecksum:  C.get_ip_checksum(cAddr) != 0,
		TCPChecksum: C.get_tcp_checksum(cAddr) != 0,
		UDPChecksum: C.get_udp_checksum(cAddr) != 0,
	}

	// В залежності від Layer заповнюємо відповідні дані
	switch Layer(addr.Layer) {
	case LayerNetwork:
		var ifIdx, subIfIdx C.uint32_t
		C.get_network_data(cAddr, &ifIdx, &subIfIdx)
		addr.Network = &NetworkData{
			IfIdx:    uint32(ifIdx),
			SubIfIdx: uint32(subIfIdx),
		}

	case LayerFlow:
		var endpointId, parentEndpointId C.uint64_t
		var processId C.uint32_t
		var localAddr, remoteAddr [4]C.uint32_t
		var localPort, remotePort C.uint16_t
		var protocol C.uint8_t

		C.get_flow_data(cAddr, &endpointId, &parentEndpointId, &processId,
			&localAddr[0], &remoteAddr[0], &localPort, &remotePort, &protocol)

		var goLocalAddr, goRemoteAddr [4]uint32
		for i := 0; i < 4; i++ {
			goLocalAddr[i] = uint32(localAddr[i])
			goRemoteAddr[i] = uint32(remoteAddr[i])
		}

		addr.Flow = &FlowData{
			EndpointId:       uint64(endpointId),
			ParentEndpointId: uint64(parentEndpointId),
			ProcessId:        uint32(processId),
			LocalAddr:        uint32ArrayToIP(goLocalAddr, addr.IPv6),
			RemoteAddr:       uint32ArrayToIP(goRemoteAddr, addr.IPv6),
			LocalPort:        uint16(localPort),
			RemotePort:       uint16(remotePort),
			Protocol:         uint8(protocol),
		}

	case LayerSocket:
		var endpointId, parentEndpointId C.uint64_t
		var processId C.uint32_t
		var localAddr, remoteAddr [4]C.uint32_t
		var localPort, remotePort C.uint16_t
		var protocol C.uint8_t

		C.get_socket_data(cAddr, &endpointId, &parentEndpointId, &processId,
			&localAddr[0], &remoteAddr[0], &localPort, &remotePort, &protocol)

		var goLocalAddr, goRemoteAddr [4]uint32
		for i := 0; i < 4; i++ {
			goLocalAddr[i] = uint32(localAddr[i])
			goRemoteAddr[i] = uint32(remoteAddr[i])
		}

		addr.Socket = &SocketData{
			EndpointId:       uint64(endpointId),
			ParentEndpointId: uint64(parentEndpointId),
			ProcessId:        uint32(processId),
			LocalAddr:        uint32ArrayToIP(goLocalAddr, addr.IPv6),
			RemoteAddr:       uint32ArrayToIP(goRemoteAddr, addr.IPv6),
			LocalPort:        uint16(localPort),
			RemotePort:       uint16(remotePort),
			Protocol:         uint8(protocol),
		}

	case LayerReflect:
		var timestamp C.int64_t
		var processId, layer C.uint32_t
		var flags C.uint64_t
		var priority C.int16_t

		C.get_reflect_data(cAddr, &timestamp, &processId, &layer, &flags, &priority)

		addr.Reflect = &ReflectData{
			Timestamp: int64(timestamp),
			ProcessId: uint32(processId),
			Layer:     uint32(layer),
			Flags:     uint64(flags),
			Priority:  int16(priority),
		}
	}

	return addr
}

func GoAddressToC(addr *Address, cAddr *C.WINDIVERT_ADDRESS) {
	// Ініціалізуємо структуру
	C.init_windivert_address(cAddr)

	cAddr.Timestamp = C.int64_t(addr.Timestamp)
	C.set_layer(cAddr, C.uint32_t(addr.Layer))
	C.set_event(cAddr, C.uint32_t(addr.Event))

	// Встановлюємо прапорці
	if addr.Sniffed {
		C.set_sniffed(cAddr, 1)
	}
	if addr.Outbound {
		C.set_outbound(cAddr, 1)
	}
	if addr.Loopback {
		C.set_loopback(cAddr, 1)
	}
	if addr.Impostor {
		C.set_impostor(cAddr, 1)
	}
	if addr.IPv6 {
		C.set_ipv6(cAddr, 1)
	}
	if addr.IPChecksum {
		C.set_ip_checksum(cAddr, 1)
	}
	if addr.TCPChecksum {
		C.set_tcp_checksum(cAddr, 1)
	}
	if addr.UDPChecksum {
		C.set_udp_checksum(cAddr, 1)
	}

	// Заповнюємо union дані в залежності від Layer
	switch Layer(addr.Layer) {
	case LayerNetwork:
		C.set_network_data(cAddr, C.uint32_t(addr.Network.IfIdx), C.uint32_t(addr.Network.SubIfIdx))

	case LayerFlow:
		localAddr := ipToUint32Array(addr.Flow.LocalAddr)
		remoteAddr := ipToUint32Array(addr.Flow.RemoteAddr)

		var cLocalAddr, cRemoteAddr [4]C.uint32_t
		for i := 0; i < 4; i++ {
			cLocalAddr[i] = C.uint32_t(localAddr[i])
			cRemoteAddr[i] = C.uint32_t(remoteAddr[i])
		}

		C.set_flow_data(cAddr, C.uint64_t(addr.Flow.EndpointId), C.uint64_t(addr.Flow.ParentEndpointId),
			C.uint32_t(addr.Flow.ProcessId), &cLocalAddr[0], &cRemoteAddr[0],
			C.uint16_t(addr.Flow.LocalPort), C.uint16_t(addr.Flow.RemotePort),
			C.uint8_t(addr.Flow.Protocol))

	case LayerSocket:
		localAddr := ipToUint32Array(addr.Socket.LocalAddr)
		remoteAddr := ipToUint32Array(addr.Socket.RemoteAddr)

		var cLocalAddr, cRemoteAddr [4]C.uint32_t
		for i := 0; i < 4; i++ {
			cLocalAddr[i] = C.uint32_t(localAddr[i])
			cRemoteAddr[i] = C.uint32_t(remoteAddr[i])
		}

		C.set_socket_data(cAddr, C.uint64_t(addr.Socket.EndpointId), C.uint64_t(addr.Socket.ParentEndpointId),
			C.uint32_t(addr.Socket.ProcessId), &cLocalAddr[0], &cRemoteAddr[0],
			C.uint16_t(addr.Socket.LocalPort), C.uint16_t(addr.Socket.RemotePort),
			C.uint8_t(addr.Socket.Protocol))

	case LayerReflect:
		C.set_reflect_data(cAddr, C.int64_t(addr.Reflect.Timestamp), C.uint32_t(addr.Reflect.ProcessId),
			C.uint32_t(addr.Reflect.Layer), C.uint64_t(addr.Reflect.Flags),
			C.int16_t(addr.Reflect.Priority))
	}
}
