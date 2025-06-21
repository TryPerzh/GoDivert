# GoDivert

GoDivert is a Go (Golang) wrapper for the [WinDivert 2.2](https://reqrypt.org/windivert.html) library.

WinDivert is a powerful user-mode packet capture, modification, and reinjection library for Windows. It provides a simple yet effective way for user-mode applications to interact with the Windows network stack at a low level.

In summary, WinDivert enables applications to:

* Capture network packets
* Filter/drop network packets
* Sniff network packets
* (Re)inject network packets
* Modify network packets




## Installation

```bash
go get github.com/TryPerzh/GoDivert
```

## Introduction

[WinDivert 2.2 documentation](https://reqrypt.org/windivert-doc.html). 

The MinGW compiler (or another) must be installed.

To compile, you need to move WinDivert64.sys or WinDivert32.sys and WinDivert.dll to the root of your project.

The wrapper implements most of the functions of WinDivert.

To access the main Windivert APIs, just import **gitlab.com/perozh/GoDivert**. It provides access to
* WinDivertOpen
* WinDivertRecv
* WinDivertRecvEx
* WinDivertSend
* WinDivertSendEx
* WinDivertShutdown
* WinDivertClose
* WinDivertSetParam
* WinDivertGetParam

**gitlab.com/perozh/GoDivert/heler** contains additional Api for working with WinDivert, which can be found in the  [documentation](https://reqrypt.org/windivert-doc.html#helper_programming_api). 

## Examples


```go
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/TryPerzh/GoDivert"
	"github.com/TryPerzh/GoDivert/helper"
)

func main() {

	filter := "true"
	layer := GoDivert.LayerNetwork
	priority := int16(1000)
	// flags := GoDivert.Flag(0)
	flags := GoDivert.FlagSniff

	wd, err := GoDivert.Open(filter, layer, priority, flags)
	if err != nil {
		fmt.Printf("Error opening WinDivert: %v\n", err)
		return
	}
	fmt.Println("WinDivert handle opened successfully.")
	defer func() {
		fmt.Println("Closing WinDivert handle...")
		if err := wd.Close(); err != nil {
			fmt.Printf("Error closing WinDivert: %v\n", err)
		} else {
			fmt.Println("WinDivert handle closed.")
		}
	}()

	packetBuffer := make([]byte, 65535)

	fmt.Println("Starting packet capture. Press Ctrl+C to stop.")

	done := make(chan os.Signal, 1)

	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-done:
			return
		default:
			n, addr, err := wd.Recv(&packetBuffer)
			if err != nil {
				fmt.Printf("Error receiving packet: %v\n", err)
				return
			}

			capturedPacket := packetBuffer[:n]
			p, err := helper.ParsePacket(capturedPacket)
			if err != nil {
				fmt.Printf("Error parsing packet: %v\n", err)
			}
			fmt.Println(p.DataLen)

			if flags&GoDivert.FlagSniff == 0 {
				_, err = wd.Send(capturedPacket, addr)
				if err != nil {
					fmt.Printf("Error sending packet: %v\n", err)
				}
			}
		}
	}

}

```

If you don't want to use helper.ParsePacket, you can refer to the library https://github.com/google/gopacket.

