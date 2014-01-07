package pcap

/*
#include <pcap.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"reflect"
	"strings"
	"time"
)

// Packet is a single packet parsed from a pcap file.
type Packet struct {
	DatalinkType int // DLT_* type
	// porting from 'pcap_pkthdr' struct
	Time   time.Time // packet send/receive time
	Caplen uint32    // bytes stored in the file (caplen <= len)
	Len    uint32    // bytes sent/received

	Data []byte // packet data

	Type        int // (next)protocol type
	DestMacAddr net.HardwareAddr
	DestMac     uint64
	SrcMacAddr  net.HardwareAddr
	SrcMac      uint64

	Headers []interface{} // decoded headers, in order
	Payload []byte        // remaining non-header bytes
}

func supportedDatalink(id int) bool {
	switch id {
	case DLTEN10MB:
		return true
	case DLTLINUXSSL:
		return true
	default:
		return false
	}
}

// Decode decodes the headers of a Packet.
func (p *Packet) Decode() {
	switch p.DatalinkType {
	// Update supportedDatalink() if you add a type here
	case C.DLT_EN10MB:
		// Ethernet
		p.Type = int(binary.BigEndian.Uint16(p.Data[12:14]))
		p.DestMacAddr = net.HardwareAddr(p.Data[0:6])
		p.DestMac = decodemac(p.Data[0:6])
		p.SrcMacAddr = net.HardwareAddr(p.Data[6:12])
		p.SrcMac = decodemac(p.Data[6:12])
		p.Payload = p.Data[14:]
	case C.DLT_LINUX_SLL:
		// Linux cooked
		// http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
		// packetType := int(binary.BigEndian.Uint16(p.Data[0:2]))
		linkLayerAddressType := int(binary.BigEndian.Uint16(p.Data[2:4]))
		linkLayerAddressLength := int(binary.BigEndian.Uint16(p.Data[4:6]))
		linkLayerAddress := p.Data[8 : 8+linkLayerAddressLength]
		protocol := int(binary.BigEndian.Uint16(p.Data[14:16]))

		p.Type = protocol
		if linkLayerAddressType == ARPHRD_ETHER {
			// Ethernet
			p.SrcMacAddr = net.HardwareAddr(linkLayerAddress)
			p.SrcMac = decodemac(linkLayerAddress)
		}
		p.Payload = p.Data[16:]
	default:
		log.Printf("unknown datalink type: %v", DatalinkValueToName(p.DatalinkType))
		return
	}

	switch p.Type {
	case TypeIP:
		p.decodeIP()
	case TypeIP6:
		p.decodeIP6()
	case TypeARP:
		p.decodeARP()
	case TypeEAPOL:
		// IEEE 802.1X.
	default:
		log.Printf("unknown protocol type for packet: %v", p.Type)
	}
}

func (p *Packet) headerString(headers []interface{}) string {
	// If there's just one header, return that.
	if len(headers) == 1 {
		if hdr, ok := headers[0].(fmt.Stringer); ok {
			return hdr.String()
		}
	}
	// If there are two headers (IPv4/IPv6 -> TCP/UDP/IP..)
	if len(headers) == 2 {
		// Commonly the first header is an address.
		if addr, ok := p.Headers[0].(addrHdr); ok {
			if hdr, ok := p.Headers[1].(addrStringer); ok {
				return fmt.Sprintf("%s %s", p.Time, hdr.String(addr))
			}
		}
	}
	// For IP in IP, we do a recursive call.
	if len(headers) >= 2 {
		if addr, ok := headers[0].(addrHdr); ok {
			if _, ok := headers[1].(addrHdr); ok {
				return fmt.Sprintf("%s > %s IP in IP: %s",
					addr.SrcAddr(), addr.DestAddr(), p.headerString(headers[1:]))
			}
		}
	}

	var typeNames []string
	for _, hdr := range headers {
		typeNames = append(typeNames, reflect.TypeOf(hdr).String())
	}

	return fmt.Sprintf("unknown [%s]", strings.Join(typeNames, ","))
}

// String prints a one-line representation of the packet header.
// The output is suitable for use in a tcpdump program.
func (p *Packet) String() string {
	// If there are no headers, print "unsupported protocol".
	if len(p.Headers) == 0 {
		return fmt.Sprintf("%s unsupported protocol %d", p.Time, int(p.Type))
	}
	return fmt.Sprintf("%s %s", p.Time, p.headerString(p.Headers))
}

func (p *Packet) decodeARP() {
	pkt := p.Payload
	arp := new(ARPHdr)
	arp.Addrtype = binary.BigEndian.Uint16(pkt[0:2])
	arp.Protocol = binary.BigEndian.Uint16(pkt[2:4])
	arp.HwAddressSize = pkt[4]
	arp.ProtAddressSize = pkt[5]
	arp.Operation = binary.BigEndian.Uint16(pkt[6:8])
	arp.SourceHwAddress = pkt[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = pkt[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestHwAddress = pkt[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DestProtAddress = pkt[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	p.Headers = append(p.Headers, arp)
	p.Payload = p.Payload[8+2*arp.HwAddressSize+2*arp.ProtAddressSize:]
}

func (p *Packet) decodeIP() {
	if len(p.Payload) < 20 {
		return
	}
	pkt := p.Payload
	ip := new(IPHdr)

	ip.Version = uint8(pkt[0]) >> 4
	ip.Ihl = uint8(pkt[0]) & 0x0F
	ip.Tos = pkt[1]
	ip.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip.ID = binary.BigEndian.Uint16(pkt[4:6])
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.Ttl = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	ip.SrcIP = pkt[12:16]
	ip.DestIP = pkt[16:20]
	pEnd := int(ip.Length)
	if pEnd > len(pkt) {
		pEnd = len(pkt)
	}
	pIhl := int(ip.Ihl) * 4
	if pIhl > pEnd {
		pIhl = pEnd
	}
	p.Payload = pkt[pIhl:pEnd]
	p.Headers = append(p.Headers, ip)

	switch ip.Protocol {
	case IPTCP:
		p.decodeTCP()
	case IPUDP:
		p.decodeUDP()
	case IPICMP:
		p.decodeICMP()
	// No ICMPv6
	case IPInIP:
		p.decodeIP()
	}
}

func (p *Packet) decodeTCP() {
	pLenPayload := len(p.Payload)
	if pLenPayload < 20 {
		return
	}
	pkt := p.Payload
	tcp := new(TCPHdr)
	tcp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	tcp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	tcp.Seq = binary.BigEndian.Uint32(pkt[4:8])
	tcp.Ack = binary.BigEndian.Uint32(pkt[8:12])
	tcp.DataOffset = (pkt[12] & 0xF0) >> 4
	tcp.Flags = binary.BigEndian.Uint16(pkt[12:14]) & 0x1FF
	tcp.Window = binary.BigEndian.Uint16(pkt[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(pkt[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(pkt[18:20])
	pDataOffset := int(tcp.DataOffset * 4)
	if pDataOffset > pLenPayload {
		pDataOffset = pLenPayload
	}
	p.Payload = pkt[pDataOffset:]
	p.Headers = append(p.Headers, tcp)
}

func (p *Packet) decodeUDP() {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	udp := new(UDPHdr)
	udp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	udp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	udp.Length = binary.BigEndian.Uint16(pkt[4:6])
	udp.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	p.Headers = append(p.Headers, udp)
	p.Payload = pkt[8:]
}

func (p *Packet) decodeICMP() {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	icmp := new(ICMPHdr)
	icmp.Type = pkt[0]
	icmp.Code = pkt[1]
	icmp.Checksum = binary.BigEndian.Uint16(pkt[2:4])
	// [4:8] are reserved and Type dependent
	// We don't look at extended ICMP
	p.Payload = pkt[8:]
	p.Headers = append(p.Headers, icmp)
}

func (p *Packet) decodeIP6() {
	if len(p.Payload) < 40 {
		return
	}
	pkt := p.Payload
	ip6 := new(IP6Hdr)
	ip6.Version = uint8(pkt[0]) >> 4
	ip6.TrafficClass = uint8((binary.BigEndian.Uint16(pkt[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = binary.BigEndian.Uint32(pkt[0:4]) & 0x000FFFFF
	ip6.Length = binary.BigEndian.Uint16(pkt[4:6])
	ip6.NextHeader = pkt[6]
	ip6.HopLimit = pkt[7]
	ip6.SrcIP = pkt[8:24]
	ip6.DestIP = pkt[24:40]
	p.Payload = pkt[40:]
	p.Headers = append(p.Headers, ip6)

	switch ip6.NextHeader {
	case IPTCP:
		p.decodeTCP()
	case IPUDP:
		p.decodeUDP()
	// No ICMP
	case IPICMPv6:
		p.decodeICMPv6()
	case IPInIP:
		p.decodeIP()
	}
}

func (p *Packet) decodeICMPv6() {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	icmpv6 := new(ICMPv6Hdr)
	icmpv6.Type = pkt[0]
	icmpv6.Code = pkt[1]
	icmpv6.Checksum = binary.BigEndian.Uint16(pkt[2:4])
	// [4:8] are reserved and Type dependent
	// We don't look at extended ICMP
	p.Payload = pkt[8:]
	p.Headers = append(p.Headers, icmpv6)
}
