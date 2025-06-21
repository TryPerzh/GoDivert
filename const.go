package GoDivert

/*
#cgo windows CFLAGS: -I${SRCDIR}/WinDivert
#cgo windows LDFLAGS: -L${SRCDIR}/WinDivert -lWinDivert -lws2_32
#include "windivert.h"

*/
import "C"

// Layer represents the different network layers where packet interception can occur.
// Each layer provides different levels of access to network traffic and operates
// at different points in the Windows network stack.
type Layer int

const (
	// LayerNetwork intercepts packets at the Network layer (OSI Layer 3).
	// This is the most commonly used layer for packet filtering and modification.
	// Packets are intercepted after routing decisions but before they are sent to the network interface.
	LayerNetwork Layer = C.WINDIVERT_LAYER_NETWORK

	// LayerNetworkForward intercepts forwarded packets at the Network layer.
	// This layer captures packets that are being forwarded by the Windows machine
	// (when acting as a router). Only available when IP forwarding is enabled.
	LayerNetworkForward Layer = C.WINDIVERT_LAYER_NETWORK_FORWARD

	// LayerFlow intercepts network flows rather than individual packets.
	// A flow represents a sequence of related packets (e.g., TCP connection).
	// This layer is useful for connection-based filtering and monitoring.
	LayerFlow Layer = C.WINDIVERT_LAYER_FLOW

	// LayerSocket intercepts packets at the Socket layer (before they enter the network stack).
	// This layer provides the earliest interception point for outbound packets
	// and the latest point for inbound packets.
	LayerSocket Layer = C.WINDIVERT_LAYER_SOCKET

	// LayerReflect is a special layer that reflects packets back to the application.
	// This layer is primarily used for testing and debugging purposes.
	LayerReflect Layer = C.WINDIVERT_LAYER_REFLECT
)

// Flag represents various behavioral flags that can be applied to a WinDivert handle.
// These flags control how the WinDivert handle processes intercepted packets.
type Flag uint32

const (
	// FlagSniff enables "sniffing" mode where packets are captured but not modified.
	// Intercepted packets are automatically re-injected into the network stack
	// without requiring explicit Send() calls. Useful for passive monitoring.
	FlagSniff Flag = C.WINDIVERT_FLAG_SNIFF

	// FlagDrop causes all intercepted packets to be automatically dropped.
	// No packets will be re-injected into the network stack.
	// This flag is useful for implementing firewall-like blocking functionality.
	FlagDrop Flag = C.WINDIVERT_FLAG_DROP

	// FlagRecvOnly restricts the handle to only receive packets.
	// Send operations will fail when this flag is set.
	// This provides additional safety for read-only packet analysis.
	FlagRecvOnly Flag = C.WINDIVERT_FLAG_RECV_ONLY

	// FlagReadOnly is an alias for FlagRecvOnly.
	// Restricts the handle to read-only operations.
	FlagReadOnly Flag = C.WINDIVERT_FLAG_READ_ONLY

	// FlagSendOnly restricts the handle to only send (inject) packets.
	// Recv operations will fail when this flag is set.
	// Useful for packet injection scenarios where reading is not required.
	FlagSendOnly Flag = C.WINDIVERT_FLAG_SEND_ONLY

	// FlagWriteOnly is an alias for FlagSendOnly.
	// Restricts the handle to write-only operations.
	FlagWriteOnly Flag = C.WINDIVERT_FLAG_WRITE_ONLY

	// FlagNoInstall prevents automatic installation of the WinDivert driver.
	// The handle can only be used if the driver is already installed and running.
	// This flag is useful in environments where driver installation is restricted.
	FlagNoInstall Flag = C.WINDIVERT_FLAG_NO_INSTALL

	// FlagFragments enables interception of fragmented IP packets.
	// By default, fragmented packets are ignored and handled by the system.
	// Setting this flag allows capture and processing of IP fragments.
	FlagFragments Flag = C.WINDIVERT_FLAG_FRAGMENTS
)

// Shutdown represents the shutdown options for a WinDivert handle.
// These values control which operations should be terminated when calling Shutdown().
type Shutdown C.UINT

const (
	// WindivertShutdownRecv terminates all pending and future Recv operations.
	// Any threads blocked on Recv() calls will return with an error.
	// Send operations remain unaffected.
	WindivertShutdownRecv Shutdown = 0x1

	// WindivertShutdownSend terminates all pending and future Send operations.
	// Any threads blocked on Send() calls will return with an error.
	// Recv operations remain unaffected.
	WindivertShutdownSend Shutdown = 0x2

	// WindivertShutdownBoth terminates both Recv and Send operations.
	// This effectively shuts down the entire handle for packet processing.
	// Note: There's a typo in the original constant name "Bith" instead of "Both".
	WindivertShutdownBith Shutdown = 0x3
)

// Param represents configurable parameters for a WinDivert handle.
// These parameters control various aspects of packet processing behavior.
type Param C.int

const (
	// ParamQueueLength controls the maximum number of packets that can be queued
	// by the WinDivert driver before packets start being dropped.
	// Default value is typically 4096 packets. Range: 32-16384.
	ParamQueueLength Param = C.WINDIVERT_PARAM_QUEUE_LENGTH

	// ParamQueueTime controls the maximum time (in milliseconds) a packet can
	// remain in the queue before being automatically dropped.
	// Default value is typically 2000ms. Range: 100-16000.
	ParamQueueTime Param = C.WINDIVERT_PARAM_QUEUE_TIME

	// ParamQueueSize controls the maximum memory (in bytes) that can be used
	// for packet queuing. When this limit is reached, new packets are dropped.
	// Default value is typically 4MB. Range: 65536-33554432.
	ParamQueueSize Param = C.WINDIVERT_PARAM_QUEUE_SIZE

	// ParamVersionMajor retrieves the major version number of the WinDivert driver.
	// This is a read-only parameter used for version compatibility checking.
	ParamVersionMajor Param = C.WINDIVERT_PARAM_VERSION_MAJOR

	// ParamVersionMinor retrieves the minor version number of the WinDivert driver.
	// This is a read-only parameter used for version compatibility checking.
	ParamVersionMinor Param = C.WINDIVERT_PARAM_VERSION_MINOR
)
