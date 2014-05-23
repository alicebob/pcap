package pcap

/*
#include <pcap.h>
*/
import "C"

import (
	"fmt"
	"net"
	"strings"
)

// Type constants.
const (
	TypeIP       = 0x0800
	TypeARP      = 0x0806
	TypeIP6      = 0x86DD
	TypeEAPOL    = 0x888E
	TypeLLDP     = 0x88CC
	TypeHomePlug = 0x88E1

	ARPHrdEther = 1
)

// Port from sf-pcap.c file.
const (
	TcpdumpMagic          = 0xa1b2c3d4
	KuznetsovTcpdumpMagic = 0xa1b2cd34
	FmesqiutaTcpdumpMagic = 0xa1b234cd
	NavtelTcpdumpMagic    = 0xa12b3c4d
	NsecTcpdumpMagic      = 0xa1b23c4d
)

const errbufSize = C.PCAP_ERRBUF_SIZE

// LinkType constants according to pcap-linktype(7).
// DLT* are the data link types. They can differ per platform.
// See http://www.tcpdump.org/linktypes.html
const (
	LinkTypeNull        = C.DLT_NULL
	LinkTypeRaw         = C.DLT_RAW
	LinkTypeEthernet    = C.DLT_EN10MB    // Ethernet (10Mb)
	LinkTypeLinuxCooked = C.DLT_LINUX_SLL // Linux cooked
)

type addrHdr interface {
	SrcAddr() string
	DestAddr() string
	Len() int
}

type addrStringer interface {
	String(addr addrHdr) string
}

func decodemac(pkt []byte) uint64 {
	mac := uint64(0)
	for i := 0; i < 6; i++ {
		mac = (mac << 8) + uint64(pkt[i])
	}
	return mac
}

// ARPHdr is a ARP packet header.
type ARPHdr struct {
	Addrtype          uint16
	Protocol          uint16
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   []byte
	SourceProtAddress []byte
	DestHwAddress     []byte
	DestProtAddress   []byte
	PayloadLength     int
}

func (arp *ARPHdr) String() (s string) {
	switch arp.Operation {
	case 1:
		s = "ARP request"
	case 2:
		s = "ARP Reply"
	}
	if arp.Addrtype == LinkTypeEthernet && arp.Protocol == TypeIP {
		s = fmt.Sprintf("%012x (%s) > %012x (%s)",
			decodemac(arp.SourceHwAddress), arp.SourceProtAddress,
			decodemac(arp.DestHwAddress), arp.DestProtAddress)
	} else {
		s = fmt.Sprintf("addrtype = %d protocol = %d", arp.Addrtype, arp.Protocol)
	}
	return
}

// Len returns the (calculated) ARP total length.
func (arp *ARPHdr) Len() int {
	return int(8 + 2*arp.HwAddressSize + 2*arp.ProtAddressSize)
}

// IPHdr is the header of an IPv4 packet.
type IPHdr struct {
	Version        uint8
	Ihl            uint8
	Tos            uint8
	Length         uint16
	ID             uint16
	Flags          uint8
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          [4]byte
	DestIP         [4]byte
	PayloadLength  int
}

// SrcAddr returns the string version of the source IP.
func (ip *IPHdr) SrcAddr() string { return net.IP(ip.SrcIP[:]).String() }

// DestAddr returns the string version of the destination IP.
func (ip *IPHdr) DestAddr() string { return net.IP(ip.DestIP[:]).String() }

// Len returns the total packet length (including headers)
func (ip *IPHdr) Len() int { return int(ip.Length) }

// Fragmented returns if the packet was fragmented
func (ip *IPHdr) Fragmented() bool {
	// Either the 'More Fragments' (MF) flag is set, or we have an offset.
	return ip.FragmentOffset > 0 || (ip.Flags&1 != 0)
}

// TCPHdr is the header of a TCP packet.
type TCPHdr struct {
	SrcPort       uint16
	DestPort      uint16
	Seq           uint32
	Ack           uint32
	DataOffset    uint8
	Flags         uint16
	Window        uint16
	Checksum      uint16
	Urgent        uint16
	PayloadLength int
}

// TCP flags.
const (
	TCPFIN = 1 << iota
	TCPSYN
	TCPRST
	TCPPSH
	TCPACK
	TCPURG
	TCPECE
	TCPCWR
	TCPNS
)

// String TODO
func (tcp *TCPHdr) String(hdr addrHdr) string {
	return fmt.Sprintf("TCP %s:%d > %s:%d %s SEQ=%d ACK=%d LEN=%d",
		hdr.SrcAddr(), int(tcp.SrcPort), hdr.DestAddr(), int(tcp.DestPort),
		tcp.FlagsString(), int64(tcp.Seq), int64(tcp.Ack), hdr.Len())
}

// FlagsString TODO
func (tcp *TCPHdr) FlagsString() string {
	var sflags []string
	if 0 != (tcp.Flags & TCPSYN) {
		sflags = append(sflags, "syn")
	}
	if 0 != (tcp.Flags & TCPFIN) {
		sflags = append(sflags, "fin")
	}
	if 0 != (tcp.Flags & TCPACK) {
		sflags = append(sflags, "ack")
	}
	if 0 != (tcp.Flags & TCPPSH) {
		sflags = append(sflags, "psh")
	}
	if 0 != (tcp.Flags & TCPRST) {
		sflags = append(sflags, "rst")
	}
	if 0 != (tcp.Flags & TCPURG) {
		sflags = append(sflags, "urg")
	}
	if 0 != (tcp.Flags & TCPNS) {
		sflags = append(sflags, "ns")
	}
	if 0 != (tcp.Flags & TCPCWR) {
		sflags = append(sflags, "cwr")
	}
	if 0 != (tcp.Flags & TCPECE) {
		sflags = append(sflags, "ece")
	}
	return fmt.Sprintf("[%s]", strings.Join(sflags, " "))
}

// UDPHdr is the header of a UDP packet.
type UDPHdr struct {
	SrcPort       uint16
	DestPort      uint16
	Length        uint16
	Checksum      uint16
	PayloadLength int
}

func (udp *UDPHdr) String(hdr addrHdr) string {
	return fmt.Sprintf("UDP %s:%d > %s:%d LEN=%d CHKSUM=%d",
		hdr.SrcAddr(), int(udp.SrcPort), hdr.DestAddr(), int(udp.DestPort),
		int(udp.Length), int(udp.Checksum))
}

// ICMPHdr is the header of an ICMP packet.
type ICMPHdr struct {
	Type          uint8
	Code          uint8
	Checksum      uint16
	ID            uint16
	Seq           uint16
	PayloadLength int
}

// String TODO
func (icmp *ICMPHdr) String(hdr addrHdr) string {
	return fmt.Sprintf("ICMP %s > %s Type = %d Code = %d ",
		hdr.SrcAddr(), hdr.DestAddr(), icmp.Type, icmp.Code)
}

// TypeString TODO
func (icmp *ICMPHdr) TypeString() (result string) {
	switch icmp.Type {
	case 0:
		result = fmt.Sprintf("Echo reply seq=%d", icmp.Seq)
	case 3:
		switch icmp.Code {
		case 0:
			result = "Network unreachable"
		case 1:
			result = "Host unreachable"
		case 2:
			result = "Protocol unreachable"
		case 3:
			result = "Port unreachable"
		default:
			result = "Destination unreachable"
		}
	case 8:
		result = fmt.Sprintf("Echo request seq=%d", icmp.Seq)
	case 30:
		result = "Traceroute"
	}
	return
}

// IP6Hdr is the header of an IPv6 packet.
type IP6Hdr struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	Version        uint8    // 4 bits
	TrafficClass   uint8    // 8 bits
	FlowLabel      uint32   // 20 bits
	Length         uint16   // 16 bits
	NextHeader     uint8    // 8 bits, similar to Protocol in IPHdr
	HopLimit       uint8    // 8 bits
	SrcIP          [16]byte // 16 bytes
	DestIP         [16]byte // 16 bytes
	HasFragmented  bool     // Is an extended header
	FragmentOffset uint16
	PayloadLength  int
}

// SrcAddr returns the string version of the source IP.
func (ip6 *IP6Hdr) SrcAddr() string { return net.IP(ip6.SrcIP[:]).String() }

// DestAddr returns the string version of the destination IP.
func (ip6 *IP6Hdr) DestAddr() string { return net.IP(ip6.DestIP[:]).String() }

// Len returns the total length of the packet
// 40 bytes are fixed header length
func (ip6 *IP6Hdr) Len() int { return int(ip6.Length) + 40 }

// Fragmented returns if the packet was fragmented
func (ip6 *IP6Hdr) Fragmented() bool {
	return ip6.HasFragmented
}

// ICMPv6Hdr is for ICMPv6
type ICMPv6Hdr struct {
	Type          uint8
	Code          uint8
	Checksum      uint16
	PayloadLength int
}

// Fragment of any protocol. Used for non-first fragments.
type Fragment struct {
	ProtocolID    uint8
	Length        int
	PayloadLength int
}
