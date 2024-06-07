package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// this magic number is the same tcpdump uses ¯\_(ツ)_/¯
	handle, err := pcap.OpenLive(os.Args[1], 262144, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("cannot open capture device %s: %s", os.Args[1], err)
		os.Exit(1)
	}
	defer handle.Close()

	// maybe have some filtering?
	// if err := handle.SetBPFFilter("port 3030"); err != nil {
	// 	panic(err)
	// }
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()

	t := time.NewTicker(time.Second)
	counters := make([]atomic.Uint64, 4096)
	for {
		select {
		case <-t.C:
			for i := 0; i < 4096; i++ {
				c := counters[i].Load()
				if c == 0 {
					continue
				}
				if i == 0 {
					fmt.Printf("none: %7d ", c)
				} else {
					fmt.Printf("vlan%d: %7d ", i, c)

				}
			}

			fmt.Printf("\n")

			for i := 0; i < 4096; i++ {
				counters[i].Store(0)
			}
		case packet := <-packets:
			go func(packet gopacket.Packet) {
				vlanPacket := packet.Layer(layers.LayerTypeDot1Q)
				if vlanPacket == nil {
					// no vlan
					counters[0].Add(1)
					return
				}

				vlan := vlanPacket.(*layers.Dot1Q)
				counters[vlan.VLANIdentifier].Add(1)
			}(packet)
		}
	}
}
