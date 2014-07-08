package pcap

/*
#include <pcap.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"reflect"
	"strings"
	"syscall"
	"time"
)

// Packet is a single packet parsed from a pcap file.
type Packet struct {
	DatalinkType int // DLT_* type
	// porting from 'pcap_pkthdr' struct
	Time    time.Time     // packet send/receive time
	Caplen  uint32        // bytes stored in the file (caplen <= len)
	Len     uint32        // bytes sent/received
	Data    []byte        // packet data
	Headers []interface{} // decoded headers, in order
	Payload []byte        // remaining captured non-header bytes
}

func supportedDatalink(id int) bool {
	switch id {
	case LinkTypeEthernet, LinkTypeLinuxCooked, LinkTypeRaw, LinkTypeNFLog:
		return true
	default:
		return false
	}
}

// Decode decodes the headers of a Packet.
func (p *Packet) Decode() {
	p.Payload = p.Data
	switch p.DatalinkType {
	// Update supportedDatalink() if you add a type here
	case LinkTypeEthernet:
		// Ethernet
		p.decodeEthernet()
		return
	case LinkTypeLinuxCooked:
		p.decodeLinuxCooked()
		return
	case LinkTypeRaw:
		// RAW. So this is IP, but it can be either v4 or v6.
		if len(p.Data) < 20 {
			return
		}
		version := uint8(p.Data[0]) >> 4
		switch version {
		case 4:
			p.decodeIP(int(p.Len))
			return
		case 6:
			p.decodeIP6(int(p.Len))
			return
		default:
			log.Printf("unknown raw packet format")
			return
		}
	case LinkTypeNFLog:
		p.decodeNFLog()
		return
	default:
		log.Printf("unknown datalink type: %v", DatalinkValueToName(p.DatalinkType))
		return
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

func (p *Packet) decodeEthernet() {
	if len(p.Payload) < 14 {
		return
	}
	eth := EthernetHdr{
		Type:          int(binary.BigEndian.Uint16(p.Payload[12:14])),
		PayloadLength: int(p.Len - 14),
	}
	copy(eth.DestMac[:], p.Payload[0:6])
	copy(eth.SrcMac[:], p.Payload[6:12])

	eth.PayloadLength = int(p.Len - 14)
	p.Payload = p.Payload[14:]
	p.Headers = append(p.Headers, &eth)
	p.handleEthernet(&eth)
}

func (p *Packet) decodeLinuxCooked() {
	// Linux cooked
	// http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
	// packetType := int(binary.BigEndian.Uint16(p.Data[0:2]))
	if len(p.Payload) < 16 {
		return
	}
	sll := EthernetHdr{
		Type: int(binary.BigEndian.Uint16(p.Payload[14:16])),
	}
	linkLayerAddressType := int(binary.BigEndian.Uint16(p.Payload[2:4]))
	linkLayerAddressLength := int(binary.BigEndian.Uint16(p.Payload[4:6]))
	linkLayerAddress := p.Payload[8 : 8+linkLayerAddressLength]
	if linkLayerAddressType == ARPHrdEther {
		// Ethernet
		copy(sll.SrcMac[:], linkLayerAddress)
		// DstMac stays zerod.
	}
	sll.PayloadLength = int(p.Len - 16)
	p.Payload = p.Payload[16:]
	p.Headers = append(p.Headers, &sll)
	p.handleEthernet(&sll)
}

// handleEthernet is the common code for decodeEthernet and decodeLinuxCooked
func (p *Packet) handleEthernet(eth *EthernetHdr) {
	if eth.Type < 0x0600 {
		// IEEE 802.3 usage: this is the frame length. We never want those.
		return
	}
	switch eth.Type {
	case TypeIP:
		p.decodeIP(eth.PayloadLength)
	case TypeIP6:
		p.decodeIP6(eth.PayloadLength)
	case TypeARP:
		p.decodeARP(eth.PayloadLength)
	case TypeEAPOL:
		// IEEE 802.1X.
	case TypeLLDP:
		// Link Layer Discovery Protocol
	case TypeHomePlug:
		// HomePlug
	default:
		log.Printf("unknown protocol type for packet: %v", eth.Type)
		// log.Printf("Src: %v\n", net.HardwareAddr(p.SrcMac).String())
		// log.Printf("Dst: %v\n", net.HardwareAddr(p.DestMac).String())
		// log.Printf("FullPayloadLength: %v\n", p.FullPayloadLength)
	}
}

// decodeNFLog handles netfilter's NFLOG format.
func (p *Packet) decodeNFLog() {
	if len(p.Data) < 4 {
		return
	}
	// NFLog messages are:
	// - A general header of 4 bytes:
	// <1byte: family><1byte: version><2byte: nflog group>
	// - then groups of:
	// <2byte:total length><2byte:header id><...content (length-4)><0..4(?) padding>
	// We are only interested in the payload header (9).
	family := uint8(p.Data[0])
	// version := uint8(p.Data[1])
	i := 4
	for i < len(p.Data) {
		headerLength := int(binary.LittleEndian.Uint16(p.Payload[i : i+2]))
		headerID := int(binary.LittleEndian.Uint16(p.Payload[i+2 : i+4]))
		if headerID == 9 {
			p.Payload = p.Payload[i+4 : i+headerLength]
			switch family {
			case syscall.AF_INET: // IP. No idea where this is defined.
				p.decodeIP(headerLength - 4)
			case syscall.AF_INET6: // TypeIP6:
				p.decodeIP6(headerLength - 4)
			}
			return
		}
		i += headerLength
		// Align to 4 byte. (Might be 8 byte, no idea)
		if i%4 != 0 {
			i += i % 4
		}
	}
}

// String prints a one-line representation of the packet header.
// The output is suitable for use in a tcpdump program.
func (p *Packet) String() string {
	// If there are no headers, print "unsupported protocol".
	if len(p.Headers) == 0 {
		return fmt.Sprintf("%s unsupported protocol", p.Time)
	}
	return fmt.Sprintf("%s %s", p.Time, p.headerString(p.Headers))
}

func (p *Packet) decodeARP(fullPayloadLength int) {
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
	headerLength := int(8 + 2*arp.HwAddressSize + 2*arp.ProtAddressSize)
	p.Payload = p.Payload[headerLength:]
	// ARP doesn't have any payload really, so we take the whole packet.
	// Limit fullPayloadLength since the packet will have ethernet padding.
	arp.PayloadLength = arp.Len()
	if fullPayloadLength < arp.PayloadLength {
		arp.PayloadLength = 0
	}
	// End of chain
}

func (p *Packet) decodeIP(fullPayloadLength int) {
	if len(p.Payload) < 20 {
		return
	}
	pkt := p.Payload
	ip := new(IPHdr)

	ip.Version = uint8(pkt[0]) >> 4
	if ip.Version != 4 {
		return
	}
	ip.Ihl = uint8(pkt[0]) & 0x0F
	ip.Tos = pkt[1]
	ip.Length = binary.BigEndian.Uint16(pkt[2:4])
	ip.ID = binary.BigEndian.Uint16(pkt[4:6])
	flagsfrags := binary.BigEndian.Uint16(pkt[6:8])
	ip.Flags = uint8(flagsfrags >> 13)
	ip.FragmentOffset = (flagsfrags & 0x1FFF)
	ip.TTL = pkt[8]
	ip.Protocol = pkt[9]
	ip.Checksum = binary.BigEndian.Uint16(pkt[10:12])
	copy(ip.SrcIP[:], pkt[12:16])
	copy(ip.DestIP[:], pkt[16:20])
	ip.PayloadLength = int(ip.Length) - int(ip.Ihl)*4 // Ihl goes per 4 bytes
	if fullPayloadLength < ip.PayloadLength {
		// Captured packet was shorter than what was expected.
		ip.PayloadLength = fullPayloadLength
	}
	if ip.PayloadLength < 0 {
		ip.PayloadLength = 0
	}
	pEnd := int(ip.Length)
	if pEnd > len(pkt) {
		pEnd = len(pkt)
	}
	pIhl := int(ip.Ihl) * 4 // Ihl is in 4-byte units
	if pIhl > pEnd {
		pIhl = pEnd
	}
	p.Payload = pkt[pIhl:pEnd]
	p.Headers = append(p.Headers, ip)

	// Don't decode non-first fragmented parts.
	// The 'More Fragments' (MF) flag is only set for the non-final packets.
	// The first fragment of a fragmented datagram has MF set and offset 0. We
	// do want to analyze that packet.
	if ip.FragmentOffset > 0 {
		p.decodeFragment(ip.Protocol, ip.PayloadLength)
		return
	}

	switch ip.Protocol {
	case syscall.IPPROTO_TCP:
		p.decodeTCP(ip.PayloadLength)
	case syscall.IPPROTO_UDP:
		p.decodeUDP(ip.PayloadLength)
	case syscall.IPPROTO_ICMP:
		p.decodeICMP(ip.PayloadLength)
	// No ICMPv6
	case syscall.IPPROTO_IPIP:
		p.decodeIP(ip.PayloadLength)
	}
}

// decodeTCP looks at the fields in payload. The complete capture length of the
// payload is passed in via payloadLength.
func (p *Packet) decodeTCP(payloadLength int) {
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
	tcp.PayloadLength = payloadLength - pDataOffset
	p.Payload = pkt[pDataOffset:]
	p.Headers = append(p.Headers, tcp)
	// End of chain
}

// decodeUDP looks at the fields in payload. The complete capture length of the
// payload is passed in via payloadLength.
func (p *Packet) decodeUDP(payloadLength int) {
	if len(p.Payload) < 8 {
		return
	}
	pkt := p.Payload
	udp := new(UDPHdr)
	udp.SrcPort = binary.BigEndian.Uint16(pkt[0:2])
	udp.DestPort = binary.BigEndian.Uint16(pkt[2:4])
	udp.Length = binary.BigEndian.Uint16(pkt[4:6])
	udp.Checksum = binary.BigEndian.Uint16(pkt[6:8])
	udp.PayloadLength = payloadLength - 8
	p.Headers = append(p.Headers, udp)
	p.Payload = pkt[8:]
	// End of chain
}

func (p *Packet) decodeICMP(payloadLength int) {
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
	icmp.PayloadLength = payloadLength - 8
	p.Headers = append(p.Headers, icmp)
	// End of chain
}

func (p *Packet) decodeIP6(fullPayloadLength int) {
	if len(p.Payload) < 40 {
		return
	}
	pkt := p.Payload
	ip6 := new(IP6Hdr)
	ip6.Version = uint8(pkt[0]) >> 4
	if ip6.Version != 6 {
		return
	}
	ip6.TrafficClass = uint8((binary.BigEndian.Uint16(pkt[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = binary.BigEndian.Uint32(pkt[0:4]) & 0x000FFFFF
	ip6.Length = binary.BigEndian.Uint16(pkt[4:6])
	ip6.PayloadLength = int(ip6.Length) // will be adjusted below
	if ip6.PayloadLength > fullPayloadLength {
		// Less bytes received than expected
		ip6.PayloadLength = fullPayloadLength
	}
	ip6.NextHeader = pkt[6]
	ip6.HopLimit = pkt[7]
	copy(ip6.SrcIP[:], pkt[8:24])
	copy(ip6.DestIP[:], pkt[24:40])
	p.Payload = pkt[40:]
	p.Headers = append(p.Headers, ip6)

	// Full list can be found
	// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
SWITCH:
	switch ip6.NextHeader {
	case syscall.IPPROTO_NONE:
		//  Extended header: none after this
	case syscall.IPPROTO_FRAGMENT:
		// Extended header: fragmented packet. 8 bytes. rfc2460
		// (we ignore the fragment information)
		if len(p.Payload) < 8 {
			return
		}
		ip6.PayloadLength -= 8 // we don't count headers as payload
		ip6.NextHeader = p.Payload[0]
		ip6.HasFragmented = true
		// Fragment offset comes in 8-byte units, we use the raw value
		ip6.FragmentOffset = (binary.BigEndian.Uint16(p.Payload[2:4]) >> 3)
		p.Payload = p.Payload[8:]
		// Only look at the content of the first packet.
		if ip6.FragmentOffset == 0 {
			goto SWITCH
		}
		p.decodeFragment(ip6.NextHeader, ip6.PayloadLength)
	case syscall.IPPROTO_HOPOPTS, // 0
		syscall.IPPROTO_DSTOPTS, // 60
		syscall.IPPROTO_ROUTING, // 43
		syscall.IPPROTO_ESP,     // 50
		syscall.IPPROTO_AH,      // 51
		135,                     // MIPv6
		139,                     // HIP
		140,                     // SHIM6
		253,                     // Experiments and testing
		254:                     // Experiments and testing
		// Various extended headers. We just skip them.
		if len(p.Payload) < 2 {
			return
		}
		ip6.NextHeader = p.Payload[0]
		headerLength := (int(p.Payload[1]) + 1) * 8
		ip6.PayloadLength -= headerLength
		p.Payload = p.Payload[headerLength:]
		goto SWITCH
	case syscall.IPPROTO_TCP:
		p.decodeTCP(ip6.PayloadLength)
	case syscall.IPPROTO_UDP:
		p.decodeUDP(ip6.PayloadLength)
	// No ICMP (v4)
	case syscall.IPPROTO_ICMPV6:
		p.decodeICMPv6(ip6.PayloadLength)
	case syscall.IPPROTO_IPIP:
		p.decodeIP(ip6.PayloadLength)
	}
}

func (p *Packet) decodeICMPv6(payloadLength int) {
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
	icmpv6.PayloadLength = payloadLength - 8
	p.Headers = append(p.Headers, icmpv6)
	// End of chain
}

// Datagram fragment
func (p *Packet) decodeFragment(protoID uint8, payloadLength int) {
	f := new(Fragment)
	f.ProtocolID = protoID
	f.Length = len(p.Payload)
	f.PayloadLength = payloadLength // It's all payload.
	p.Headers = append(p.Headers, f)
	// End of chain
}
