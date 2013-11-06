package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/alicebob/pcap"
)

func min(x uint32, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

func main() {
	var (
		device = flag.String("d", "", "device")
		file   = flag.String("r", "", "file")
		expr   = flag.String("e", "", "filter expression")
	)
	flag.Parse()
	log.SetOutput(os.Stdout)

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for i := range ifs {
		log.Printf("dev %d: %s (%s)", i+1, ifs[i].Name, ifs[i].Description)
	}

	var h *pcap.Pcap
	if *device != "" {
		h, err = pcap.OpenLive(*device, 65535, true, 0)
		if err != nil {
			log.Fatalf("OpenLive(%s) failed: %s", *device, err)
		}
	} else if *file != "" {
		h, err = pcap.OpenOffline(*file)
		if err != nil {
			log.Fatalf("Openoffline(%s) failed: %s", *file, err)
		}
	} else {
		log.Fatalf("usage: pcaptest [-d <device> | -r <file>]")
	}

	log.Printf("pcap version: %s", pcap.Version())

	if *expr != "" {
		log.Printf("Setting filter: %s", *expr)
		if err := h.SetFilter(*expr); err != nil {
			log.Printf("Warning: setting filter failed: %s", err)
		}
	}

	for {
		pkt := h.Next()
		if pkt == nil {
			break
		}
		fmt.Printf(
			"time: %d.%06d (%s) caplen: %d len: %d\nData:",
			int64(pkt.Time.Second()),
			int64(pkt.Time.Nanosecond()/1e3),
			time.Unix(int64(pkt.Time.Second()), 0).String(),
			int64(pkt.Caplen),
			int64(pkt.Len),
		)
		for i := uint32(0); i < pkt.Caplen; i++ {
			if i%32 == 0 {
				fmt.Printf("\n")
			}
			if 32 <= pkt.Data[i] && pkt.Data[i] <= 126 {
				fmt.Printf("%c", pkt.Data[i])
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Printf("\n\n")
	}
}
