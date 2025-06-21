package GoDivert

/*
#cgo windows CFLAGS: -I${SRCDIR}/WinDivert
#cgo windows LDFLAGS: -L${SRCDIR}/WinDivert -lWinDivert -lws2_32
#include "windivert.h"
*/
import "C"
import (
	"fmt"
	"runtime"
	"strings"
)

// lastError returns an error containing a human-readable description of the last
// error encountered by a call to a WinDivert function.  The error is based on
// the value returned by GetLastError().
func lastError() error {
	code := C.GetLastError()

	pc, _, _, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("error code %d", code)
	}
	callerFunc := runtime.FuncForPC(pc).Name()
	parts := strings.Split(callerFunc, ".")
	simpleFuncName := parts[len(parts)-1] // Get the last part (function name)

	switch simpleFuncName {
	case "WinDivertOpen":
		switch code {
		case 2:
			return fmt.Errorf("%s: ERROR_FILE_NOT_FOUND (2): WinDivert32.sys or WinDivert64.sys driver files not found", simpleFuncName)
		case 5:
			return fmt.Errorf("%s: ERROR_ACCESS_DENIED (5): The calling program does not have administrator privileges", simpleFuncName)
		case 87:
			return fmt.Errorf("%s: ERROR_INVALID_PARAMETER (87): Invalid packet filter string, layer, priority, or flags", simpleFuncName)
		case 557:
			return fmt.Errorf("%s: ERROR_INVALID_IMAGE_HASH (557): WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature", simpleFuncName)
		case 654:
			return fmt.Errorf("%s: ERROR_DRIVER_FAILED_PRIOR_UNLOAD (654): An incompatible version of the WinDivert driver is currently loaded", simpleFuncName)
		case 1060:
			return fmt.Errorf("%s: ERROR_SERVICE_DOES_NOT_EXIST (1060): The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag, and the WinDivert driver is not yet installed", simpleFuncName)
		case 1275:
			return fmt.Errorf("%s: ERROR_DRIVER_BLOCKED (1275): The WinDivert driver is blocked by security software, or you are using a virtualization environment that does not support drivers", simpleFuncName)
		case 1753:
			return fmt.Errorf("%s: EPT_S_NOT_REGISTERED (1753): This error occurs when the Base Filtering Engine service is disabled", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	case "WinDivertRecv":
		switch code {
		case 122:
			return fmt.Errorf("%s: ERROR_INSUFFICIENT_BUFFER (122): Invalid buffer", simpleFuncName)
		case 232:
			return fmt.Errorf("%s: ERROR_NO_DATA (232): No data available in the buffer", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	case "WinDivertSend":
		switch code {
		case 1232:
			return fmt.Errorf("%s: ERROR_HOST_UNREACHABLE (1232): Unable to connect to the host", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	case "Open":
		switch code {
		case 2:
			return fmt.Errorf("%s: ERROR_FILE_NOT_FOUND (2): WinDivert32.sys or WinDivert64.sys driver files not found", simpleFuncName)
		case 5:
			return fmt.Errorf("%s: ERROR_ACCESS_DENIED (5): The calling program does not have administrator privileges", simpleFuncName)
		case 87:
			return fmt.Errorf("%s: ERROR_INVALID_PARAMETER (87): Invalid packet filter string, layer, priority, or flags", simpleFuncName)
		case 557:
			return fmt.Errorf("%s: ERROR_INVALID_IMAGE_HASH (557): WinDivert32.sys or WinDivert64.sys driver does not have a valid digital signature", simpleFuncName)
		case 654:
			return fmt.Errorf("%s: ERROR_DRIVER_FAILED_PRIOR_UNLOAD (654): An incompatible version of the WinDivert driver is currently loaded", simpleFuncName)
		case 1060:
			return fmt.Errorf("%s: ERROR_SERVICE_DOES_NOT_EXIST (1060): The handle was opened with the WINDIVERT_FLAG_NO_INSTALL flag, and the WinDivert driver is not yet installed", simpleFuncName)
		case 1275:
			return fmt.Errorf("%s: ERROR_DRIVER_BLOCKED (1275): The WinDivert driver is blocked by security software, or you are using a virtualization environment that does not support drivers", simpleFuncName)
		case 1753:
			return fmt.Errorf("%s: EPT_S_NOT_REGISTERED (1753): This error occurs when the Base Filtering Engine service is disabled", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	case "Recv":
		switch code {
		case 122:
			return fmt.Errorf("%s: ERROR_INSUFFICIENT_BUFFER (122): Invalid buffer", simpleFuncName)
		case 232:
			return fmt.Errorf("%s: ERROR_NO_DATA (232): No data available in the buffer", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	case "Send":
		switch code {
		case 1232:
			return fmt.Errorf("%s: ERROR_HOST_UNREACHABLE (1232): Unable to connect to the host", simpleFuncName)
		default:
			return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
		}
	default:
		return fmt.Errorf("%s failed: error code %d", simpleFuncName, code)
	}
}
