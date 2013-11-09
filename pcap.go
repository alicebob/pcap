// Package pcap is a wrapper around the pcap library.
package pcap

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>

// Workaround for not knowing how to cast to const u_char**
int hack_pcap_next_ex(pcap_t * p, struct pcap_pkthdr **pkt_header,
		      u_char ** pkt_data)
{
	return pcap_next_ex(p, pkt_header, (const u_char **)pkt_data);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

type Pcap struct {
	cptr *C.pcap_t
}

type pcapError struct{ string }

type Stat struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

type Interface struct {
	Name        string
	Description string
	Addresses   []IFAddress
	// TODO: add more elements
}

type IFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

func Version() string               { return C.GoString(C.pcap_lib_version()) }
func (p *Pcap) Datalink() int       { return int(C.pcap_datalink(p.cptr)) }
func (e *pcapError) Error() string  { return e.string }
func (p *Pcap) Geterror() error     { return &pcapError{C.GoString(C.pcap_geterr(p.cptr))} }
func (p *Pcap) Next() (pkt *Packet) { rv, _ := p.NextEx(); return rv }

func Create(device string) (*Pcap, error) {
	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	buf := (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	cptr := C.pcap_create(dev, buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr: cptr,
	}, nil
}

// Set buffer size (units in bytes) on activated handle.
func (p *Pcap) SetBufferSize(sz int32) error {
	if C.pcap_set_buffer_size(p.cptr, C.int(sz)) != 0 {
		return p.Geterror()
	}
	return nil
}

// If arg p is non-zero promiscuous mode will be set on capture handle when it
// is activated.
func (p *Pcap) SetPromisc(promisc bool) error {
	pro := int32(0)
	if promisc {
		pro = 1
	}

	if C.pcap_set_promisc(p.cptr, C.int(pro)) != 0 {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) SetSnapLen(s int32) error {
	if C.pcap_set_snaplen(p.cptr, C.int(s)) != 0 {
		return p.Geterror()
	}
	return nil
}

// Set read timeout (milliseconds) that will be used on a capture handle when it
// is activated.
func (p *Pcap) SetReadTimeout(toMs int32) error {
	if C.pcap_set_timeout(p.cptr, C.int(toMs)) != 0 {
		return p.Geterror()
	}
	return nil
}

// Activate a packet capture handle to look at packets on the network, with the
// options that were set on the handle being in effect.
func (p *Pcap) Activate() error {
	if C.pcap_activate(p.cptr) != 0 {
		return p.Geterror()
	}
	return nil
}

// OpenLive opens a device and returns a handler.
func OpenLive(device string, snaplen int32, promisc bool, timeout_ms int32) (*Pcap, error) {
	buf := (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	pro := int32(0)
	if promisc {
		pro = 1
	}

	cptr := C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeout_ms), buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr: cptr,
	}, nil
}

// OpenOffline provides a Pcap over a .pcap file.
func OpenOffline(file string) (*Pcap, error) {
	buf := (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	cptr := C.pcap_open_offline(cf, buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr: cptr,
	}, nil
}

// Pcap closes a handler.
func (p *Pcap) Close() {
	C.pcap_close(p.cptr)
}

func (p *Pcap) NextEx() (*Packet, int32) {
	var pkthdr *C.struct_pcap_pkthdr
	var bufPtr *C.u_char
	result := int32(C.hack_pcap_next_ex(p.cptr, &pkthdr, &bufPtr))
	buf := unsafe.Pointer(bufPtr)
	if buf == nil {
		return nil, result
	}

	pkt := &Packet{
		Time:   time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)),
		Caplen: uint32(pkthdr.caplen),
		Len:    uint32(pkthdr.len),
		Data:   make([]byte, pkthdr.caplen),
	}
	for i := uint32(0); i < pkt.Caplen; i++ {
		pkt.Data[i] = *(*byte)(unsafe.Pointer(uintptr(buf) + uintptr(i)))
	}
	return pkt, result
}

func (p *Pcap) Getstats() (*Stat, error) {
	var cstats _Ctype_struct_pcap_stat
	if C.pcap_stats(p.cptr, &cstats) == -1 {
		return nil, p.Geterror()
	}

	return &Stat{
		PacketsReceived:  uint32(cstats.ps_recv),
		PacketsDropped:   uint32(cstats.ps_drop),
		PacketsIfDropped: uint32(cstats.ps_ifdrop),
	}, nil
}

func (p *Pcap) SetFilter(expr string) error {
	var bpf _Ctype_struct_bpf_program
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	if C.pcap_compile(p.cptr, &bpf, cexpr, 1, 0) == -1 {
		return p.Geterror()
	}
	defer C.pcap_freecode(&bpf)

	if C.pcap_setfilter(p.cptr, &bpf) == -1 {
		return p.Geterror()
	}
	return nil
}

func (p *Pcap) SetDataLink(dlt int) error {
	if -1 == C.pcap_set_datalink(p.cptr, C.int(dlt)) {
		return p.Geterror()
	}
	return nil
}

func DatalinkValueToName(dlt int) string {
	if name := C.pcap_datalink_val_to_name(C.int(dlt)); name != nil {
		return C.GoString(name)
	}
	return ""
}

func DatalinkValueToDescription(dlt int) string {
	if desc := C.pcap_datalink_val_to_description(C.int(dlt)); desc != nil {
		return C.GoString(desc)
	}
	return ""
}

func FindAllDevs() ([]Interface, error) {
	buf := (*C.char)(C.calloc(ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	var alldevsp *C.pcap_if_t
	if C.pcap_findalldevs((**C.pcap_if_t)(&alldevsp), buf) == -1 {
		return nil, errors.New(C.GoString(buf))
	}
	defer C.pcap_freealldevs((*C.pcap_if_t)(alldevsp))

	ifs := []Interface{}
	for dev := alldevsp; dev != nil; dev = (*C.pcap_if_t)(dev.next) {
		ifs = append(ifs, Interface{
			Name:        C.GoString(dev.name),
			Description: C.GoString(dev.description),
			Addresses:   findAllAddresses(dev.addresses),
			// TODO: add more elements
		})
	}
	return ifs, nil
}

func findAllAddresses(addresses *_Ctype_struct_pcap_addr) []IFAddress {
	// TODO - make it support more than IPv4 and IPv6?
	a := []IFAddress{}
	for curaddr := addresses; curaddr != nil; curaddr = (*_Ctype_struct_pcap_addr)(curaddr.next) {
		if curaddr.addr == nil {
			continue
		}

		ip, err := sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr)))
		if err != nil {
			continue
		}
		netmask, err := sockaddrToIP((*syscall.RawSockaddr)(unsafe.Pointer(curaddr.addr)))
		if err != nil {
			continue
		}

		a = append(a, IFAddress{
			IP:      ip,
			Netmask: netmask,
		})
	}
	return a
}

func sockaddrToIP(rsa *syscall.RawSockaddr) ([]byte, error) {
	switch rsa.Family {
	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		ip := make([]byte, 4)
		for i := 0; i < len(ip); i++ {
			ip[i] = pp.Addr[i]
		}
		return ip, nil

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		ip := make([]byte, 16)
		for i := 0; i < len(ip); i++ {
			ip[i] = pp.Addr[i]
		}
		return ip, nil

	default:
		return nil, fmt.Errorf("unsupported address type %d", rsa.Family)
	}
}

// Inject TODO
func (p *Pcap) Inject(data []byte) error {
	buf := (*C.char)(C.malloc((C.size_t)(len(data))))
	defer C.free(unsafe.Pointer(buf))

	for i := 0; i < len(data); i++ {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(buf)) + uintptr(i))) = data[i]
	}

	if C.pcap_inject(p.cptr, unsafe.Pointer(buf), (C.size_t)(len(data))) == -1 {
		return p.Geterror()
	}
	return nil
}
