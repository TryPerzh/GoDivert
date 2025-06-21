package GoDivert

/*
#cgo windows CFLAGS: -I${SRCDIR}/WinDivert
#cgo windows LDFLAGS: -L${SRCDIR}/WinDivert -lWinDivert -lws2_32
#include "windivert.h"
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"
)

// GoDivert provides a Go-safe wrapper around the WinDivert handle, offering
// synchronized access to packet interception and injection functionality.
type GoDivert struct {
	m      sync.RWMutex
	handle C.HANDLE
	closed bool
}

// Open initializes and opens a WinDivert handle with the specified filter, layer,
// priority, and flags. It returns a GoDivert instance if successful, or an error
// if the operation fails. The filter cannot be empty. The handle must be closed
// using the Close method when no longer needed to release resources.
func Open(filter string, layer Layer, priority int16, flags Flag) (*GoDivert, error) {
	if filter == "" {
		return nil, fmt.Errorf("filter cannot be empty")
	}
	cfilter := C.CString(filter)
	defer C.free(unsafe.Pointer(cfilter))
	handle := C.WinDivertOpen(
		cfilter,
		C.WINDIVERT_LAYER(layer),
		C.INT16(priority),
		C.UINT64(flags),
	)
	if handle == C.HANDLE(C.INVALID_HANDLE_VALUE) {
		return nil, fmt.Errorf("failed to open WinDivert: %w", lastError())
	}
	return &GoDivert{
		handle: handle,
		closed: false,
	}, nil
}

// Close releases the WinDivert handle associated with the GoDivert instance.
// It locks the mutex to ensure that no other operations are performed on the
// handle while it is being closed. If the handle is already closed, it returns
// immediately without error. If the close operation fails, it returns an error
// indicating the failure. Upon successful closure, it marks the handle as closed.
func (gd *GoDivert) Close() error {
	gd.m.Lock()
	defer gd.m.Unlock()
	if gd.closed {
		return nil
	}
	b := C.WinDivertClose(gd.handle)
	if b == 0 {
		return fmt.Errorf("failed to close WinDivert: %w", lastError())
	}
	gd.closed = true
	return nil
}

// Recv captures a packet and stores it in the given buffer. It returns the
// number of bytes captured, the address of the packet, and an error if the
// operation fails. The buffer must be large enough to hold the captured packet.
// If the GoDivert handle is closed, it returns an error immediately.
func (gd *GoDivert) RecvOld(buffer *[]byte) (uint, *C.WINDIVERT_ADDRESS, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, nil, fmt.Errorf("GoDivert handle is closed")
	}
	var recvLen C.UINT
	var addr C.WINDIVERT_ADDRESS
	b := C.WinDivertRecv(
		gd.handle,
		unsafe.Pointer(&(*buffer)[0]),
		C.UINT(len(*buffer)),
		&recvLen,
		&addr,
	)
	if b == 0 {
		return 0, nil, lastError()
	}
	return uint(recvLen), &addr, nil
}

func (gd *GoDivert) Recv(buffer *[]byte) (uint, *Address, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, nil, fmt.Errorf("GoDivert handle is closed")
	}
	var recvLen C.UINT
	var cAddr C.WINDIVERT_ADDRESS
	b := C.WinDivertRecv(
		gd.handle,
		unsafe.Pointer(&(*buffer)[0]),
		C.UINT(len(*buffer)),
		&recvLen,
		&cAddr,
	)
	if b == 0 {
		return 0, nil, lastError()
	}

	goAddr := CAddressToGo(&cAddr)

	return uint(recvLen), goAddr, nil
}

// RecvEx captures a packet and stores it in the given buffer. It returns the
// number of bytes captured, the address of the packet, and an error if the
// operation fails. The buffer must be large enough to hold the captured packet.
// If the GoDivert handle is closed, it returns an error immediately.
// The flags argument can be used to customize the receive operation.
func (gd *GoDivert) RecvExOld(buffer *[]byte, flags Flag) (uint, *C.WINDIVERT_ADDRESS, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, nil, fmt.Errorf("GoDivert handle is closed")
	}
	var recvLen C.UINT
	var addr C.WINDIVERT_ADDRESS
	var addrLen C.UINT = C.UINT(unsafe.Sizeof(addr))
	b := C.WinDivertRecvEx(
		gd.handle,
		unsafe.Pointer(&(*buffer)[0]),
		C.UINT(len(*buffer)),
		&recvLen,
		C.UINT64(flags),
		&addr,
		&addrLen,
		nil,
	)
	if b == 0 {
		return 0, nil, lastError()
	}
	return uint(recvLen), &addr, nil
}

func (gd *GoDivert) RecvEx(buffer *[]byte, flags Flag) (uint, *Address, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, nil, fmt.Errorf("GoDivert handle is closed")
	}
	var recvLen C.UINT
	var cAddr C.WINDIVERT_ADDRESS
	var addrLen C.UINT = C.UINT(unsafe.Sizeof(cAddr))
	b := C.WinDivertRecvEx(
		gd.handle,
		unsafe.Pointer(&(*buffer)[0]),
		C.UINT(len(*buffer)),
		&recvLen,
		C.UINT64(flags),
		&cAddr,
		&addrLen,
		nil,
	)
	if b == 0 {
		return 0, nil, lastError()
	}

	goAddr := CAddressToGo(&cAddr)

	return uint(recvLen), goAddr, nil
}

// Send transmits a packet using the specified buffer and address. It returns the
// number of bytes sent and an error if the operation fails. If the GoDivert handle
// is closed, it returns an error immediately. The buffer must contain the packet
// data to be sent, and the address specifies the packet's destination. The function
// locks the mutex for reading to ensure thread safety during the send operation.
func (gd *GoDivert) SendOld(buffer []byte, addr *C.WINDIVERT_ADDRESS) (uint, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, fmt.Errorf("GoDivert handle is closed")
	}
	var sendLen C.UINT
	var caddr C.WINDIVERT_ADDRESS = (C.WINDIVERT_ADDRESS)(*addr)
	b := C.WinDivertSend(
		gd.handle,
		unsafe.Pointer(&buffer[0]),
		C.UINT(len(buffer)),
		&sendLen,
		&caddr,
	)
	if b == 0 {
		return 0, fmt.Errorf("Send failed: %w", lastError())
	}
	return uint(sendLen), nil
}

func (gd *GoDivert) Send(buffer []byte, addr *Address) (uint, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, fmt.Errorf("GoDivert handle is closed")
	}
	var sendLen C.UINT
	var cAddr C.WINDIVERT_ADDRESS
	GoAddressToC(addr, &cAddr)
	b := C.WinDivertSend(
		gd.handle,
		unsafe.Pointer(&buffer[0]),
		C.UINT(len(buffer)),
		&sendLen,
		&cAddr,
	)
	if b == 0 {
		return 0, fmt.Errorf("Send failed: %w", lastError())
	}
	return uint(sendLen), nil
}

// SendEx transmits a packet using the specified buffer and address. It returns the
// number of bytes sent and an error if the operation fails. If the GoDivert handle
// is closed, it returns an error immediately. The buffer must contain the packet
// data to be sent, and the address specifies the packet's destination. The flags
// argument can be used to customize the send operation. The function locks the
// mutex for reading to ensure thread safety during the send operation.
func (gd *GoDivert) SendExOld(buffer []byte, flags Flag, addr *C.WINDIVERT_ADDRESS) (uint, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, fmt.Errorf("GoDivert handle is closed")
	}
	var sendLen C.UINT
	var caddr C.WINDIVERT_ADDRESS = (C.WINDIVERT_ADDRESS)(*addr)
	var caddrLen C.UINT = C.UINT(unsafe.Sizeof(caddr))
	b := C.WinDivertSendEx(
		gd.handle,
		unsafe.Pointer(&buffer[0]),
		C.UINT(len(buffer)),
		&sendLen,
		C.UINT64(flags),
		&caddr,
		caddrLen,
		nil,
	)
	if b == 0 {
		return 0, fmt.Errorf("SendEx failed: %w", lastError())
	}
	return uint(sendLen), nil
}

func (gd *GoDivert) SendEx(buffer []byte, flags Flag, addr *Address) (uint, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, fmt.Errorf("GoDivert handle is closed")
	}
	var sendLen C.UINT
	var cAddr C.WINDIVERT_ADDRESS
	GoAddressToC(addr, &cAddr)
	var caddrLen C.UINT = C.UINT(unsafe.Sizeof(cAddr))
	b := C.WinDivertSendEx(
		gd.handle,
		unsafe.Pointer(&buffer[0]),
		C.UINT(len(buffer)),
		&sendLen,
		C.UINT64(flags),
		&cAddr,
		caddrLen,
		nil,
	)
	if b == 0 {
		return 0, fmt.Errorf("SendEx failed: %w", lastError())
	}
	return uint(sendLen), nil
}

// Shutdown shuts down the WinDivert handle associated with the GoDivert
// instance. The how argument specifies which direction of traffic to
// shut down. The function locks the mutex for reading to ensure thread
// safety during the shutdown operation. If the handle is already closed,
// it returns an error immediately. If the shutdown operation fails, it
// returns an error indicating the failure. Upon successful shutdown, it
// marks the handle as closed.
func (gd *GoDivert) Shutdown(how Shutdown) error {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return fmt.Errorf("GoDivert handle is closed")
	}
	b := C.WinDivertShutdown(
		gd.handle,
		C.WINDIVERT_SHUTDOWN(how),
	)
	if b == 0 {
		return fmt.Errorf("Shutdown failed: %w", lastError())
	}
	return nil
}

// SetParam sets a parameter for the WinDivert handle associated with the
// GoDivert instance. The param argument specifies which parameter to set,
// and the value argument specifies the new value for the parameter. The
// function locks the mutex for reading to ensure thread safety during the
// operation. If the handle is closed, it returns an error immediately. If
// the operation fails, it returns an error indicating the failure.
func (gd *GoDivert) SetParam(param Param, value uint64) error {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return fmt.Errorf("GoDivert handle is closed")
	}
	b := C.WinDivertSetParam(
		gd.handle,
		C.WINDIVERT_PARAM(param),
		C.UINT64(value),
	)
	if b == 0 {
		return fmt.Errorf("SetParam failed: %w", lastError())
	}
	return nil
}

// GetParam retrieves the value of a parameter for the WinDivert handle associated
// with the GoDivert instance. The param argument specifies which parameter to
// retrieve, and the returned value is the current value of that parameter. The
// function locks the mutex for reading to ensure thread safety during the
// operation. If the handle is closed, it returns an error immediately. If the
// operation fails, it returns an error indicating the failure.
func (gd *GoDivert) GetParam(param Param) (uint64, error) {
	gd.m.RLock()
	defer gd.m.RUnlock()
	if gd.closed {
		return 0, fmt.Errorf("GoDivert handle is closed")
	}
	var value C.UINT64
	b := C.WinDivertGetParam(
		gd.handle,
		C.WINDIVERT_PARAM(param),
		&value,
	)
	if b == 0 {
		return 0, fmt.Errorf("GetParam failed: %w", lastError())
	}
	return uint64(value), nil
}
