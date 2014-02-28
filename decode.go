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
	TypeIP    = 0x0800
	TypeARP   = 0x0806
	TypeIP6   = 0x86DD
	TypeEAPOL = 0x888E

	ARPHRD_ETHER = 1
)

// Port from sf-pcap.c file.
const (
	TcpdumpMagic          = 0xa1b2c3d4
	KuznetsovTcpdumpMagic = 0xa1b2cd34
	FmesqiutaTcpdumpMagic = 0xa1b234cd
	NavtelTcpdumpMagic    = 0xa12b3c4d
	NsecTcpdumpMagic      = 0xa1b23c4d
)

// DLT* are the data link types. They can differ per platform.
// See http://www.tcpdump.org/linktypes.html
const (
	DLTNULL     = C.DLT_NULL
	DLTRAW      = C.DLT_RAW
	DLTEN10MB   = C.DLT_EN10MB    // Ethernet (10Mb)
	DLTEN3MB    = C.DLT_EN3MB     // Experimental Ethernet (3Mb)
	DLTAX25     = C.DLT_AX25      // Amateur Radio AX.25
	DLTPRONET   = C.DLT_PRONET    // Proteon ProNET Token Ring
	DLTCHAOS    = C.DLT_CHAOS     // Chaos
	DLTIEEE802  = C.DLT_IEEE802   // 802.5 Token Ring
	DLTARCNET   = C.DLT_ARCNET    // ARCNET, with BSD-style header
	DLTSLIP     = C.DLT_SLIP      // Serial Line IP
	DLTPPP      = C.DLT_PPP       // Point-to-point Protocol
	DLTFDDI     = C.DLT_FDDI      // FDDI
	DLTLINUXSSL = C.DLT_LINUX_SLL // Linux cooked
)

const errbufSize = C.PCAP_ERRBUF_SIZE

// LinkType constants according to pcap-linktype(7).
const (
	LinkTypeNull      = DLTNULL
	LinkTypeEthernet  = DLTEN10MB
	LinkTypeTokenRing = DLTIEEE802

	LinkTypeExpEthernet = DLTEN3MB /* 3Mb experimental Ethernet */
	LinkTypeAX25        = DLTAX25
	LinkTypePRONET      = DLTPRONET
	LinkTypeCHAOS       = DLTCHAOS
	LinkTypeARCNETBSD   = DLTARCNET /* BSD-style headers */
	LinkTypeSLIP        = DLTSLIP
	LinkTypePPP         = DLTPPP
	LinkTypeFDDI        = DLTFDDI

	LinkTypeARCNET         = 7
	LinkTypeATMRFC1483     = 100
	LinkTypeRAW            = 101
	LinkTypePPPHDLC        = 50
	LinkTypePPPETHER       = 51
	LinkTypeCHDLC          = 104
	LinkTypeIEEE80211      = 105
	LinkTypeFRELAY         = 107
	LinkTypeLOOP           = 108
	LinkTypeLINUXSLL       = 113
	LinkTypeLTALK          = 104
	LinkTypePFLOG          = 117
	LinkTypePRISMHeader    = 119
	LinkTypeIPOverFC       = 122
	LinkTypeSUNATM         = 123
	LinkTypeIEEE80211Radio = 127
	LinkTypeARCNETLinux    = 129
	LinkTypeLinuxIRDA      = 144
	LinkTypeLinuxLAPD      = 177
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

// IPHdr is the header of an IP packet.
type IPHdr struct {
	Version        uint8
	Ihl            uint8
	Tos            uint8
	Length         uint16
	ID             uint16
	Flags          uint8
	FragmentOffset uint16
	Ttl            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          []byte
	DestIP         []byte
	PayloadLength  int
}

// SrcAddr returns the string version of the source IP.
func (ip *IPHdr) SrcAddr() string { return net.IP(ip.SrcIP).String() }

// DestAddr returns the string version of the destination IP.
func (ip *IPHdr) DestAddr() string { return net.IP(ip.DestIP).String() }

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
	Data          []byte
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
	Data          []byte
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
	Version        uint8  // 4 bits
	TrafficClass   uint8  // 8 bits
	FlowLabel      uint32 // 20 bits
	Length         uint16 // 16 bits
	NextHeader     uint8  // 8 bits, similar to Protocol in IPHdr
	HopLimit       uint8  // 8 bits
	SrcIP          []byte // 16 bytes
	DestIP         []byte // 16 bytes
	HasFragmented  bool   // Is an extended header
	FragmentOffset uint16
	PayloadLength  int
}

// SrcAddr returns the string version of the source IP.
func (ip6 *IP6Hdr) SrcAddr() string { return net.IP(ip6.SrcIP).String() }

// DestAddr returns the string version of the destination IP.
func (ip6 *IP6Hdr) DestAddr() string { return net.IP(ip6.DestIP).String() }

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
