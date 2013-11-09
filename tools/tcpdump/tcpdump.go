package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/alicebob/pcap"
)

func main() {
	var (
		device  = flag.String("i", "", "interface")
		snaplen = flag.Int("s", 65535, "snaplen")
		hex     = flag.Bool("X", false, "hexdump")
	)
	flag.Usage = func() {
		log.Fatalf("usage: %s [ -i interface ] [ -s snaplen ] [ -X ] [ expression ]\n", os.Args[0])
	}
	flag.Parse()

	expr := ""
	if len(flag.Args()) > 0 {
		expr = flag.Arg(0)
	}

	if *device == "" {
		devs, err := pcap.FindAllDevs()
		if err != nil {
			log.Printf("tcpdump: couldn't find any devices: %s", err)
		}
		if len(devs) == 0 {
			flag.Usage()
		}
		*device = devs[0].Name
	}

	h, err := pcap.OpenLive(*device, int32(*snaplen), true, 1000)
	if h == nil {
		log.Printf("tcpdump: %s", err)
		return
	}

	if expr != "" {
		ferr := h.SetFilter(expr)
		if ferr != nil {
			log.Printf("tcpdump: %s", ferr)
		}
	}

	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		fmt.Printf("%s\n", pkt.String())
		if *hex {
			hexdump(pkt)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func hexdump(pkt *pcap.Packet) {
	for i := 0; i < len(pkt.Data); i += 16 {
		dumpline(uint32(i), pkt.Data[i:min(i+16, len(pkt.Data))])
	}
}

func dumpline(addr uint32, line []byte) {
	fmt.Printf("\t0x%04x: ", int32(addr))
	var i uint16
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if i%2 == 0 {
			fmt.Printf(" ")
		}
		fmt.Printf("%02x", line[i])
	}
	for j := i; j <= 16; j++ {
		if j%2 == 0 {
			fmt.Printf(" ")
		}
		fmt.Printf("  ")
	}
	fmt.Printf("  ")
	for i = 0; i < 16 && i < uint16(len(line)); i++ {
		if line[i] >= 32 && line[i] <= 126 {
			fmt.Printf("%c", line[i])
		} else {
			fmt.Printf(".")
		}
	}
	fmt.Printf("\n")
}
