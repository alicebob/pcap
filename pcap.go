// Package pcap is a wrapper around the pcap library.
package pcap

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>
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

// Pcap wraps a pcap_t struct.
type Pcap struct {
	cptr     *C.pcap_t
	sampling int // 1:N; a bit of a hack
}

type pcapError struct{ string }

// Stat records statistics about packets received and dropped.
type Stat struct {
	PacketsReceived  uint32
	PacketsDropped   uint32
	PacketsIfDropped uint32
}

// Interface describes a single network interface on a host.
type Interface struct {
	Name        string
	Description string
	Addresses   []IFAddress
	// TODO: add more elements
}

// IFAddress is the interface address.
type IFAddress struct {
	IP      net.IP
	Netmask net.IPMask
	// TODO: add broadcast + PtP dst ?
}

// Version returns the current pcap library version.
func Version() string { return C.GoString(C.pcap_lib_version()) }

// Datalink TODO
func (p *Pcap) Datalink() int { return int(C.pcap_datalink(p.cptr)) }

func (e *pcapError) Error() string { return e.string }

// Geterror converts the last pcap error to a Go error.
func (p *Pcap) Geterror() error { return &pcapError{C.GoString(C.pcap_geterr(p.cptr))} }

// Next wraps libpcap NextEx
func (p *Pcap) Next() (pkt *Packet) { rv, _ := p.NextEx(); return rv }

// Create TODO
func Create(device string) (*Pcap, error) {
	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	buf := (*C.char)(C.calloc(errbufSize, 1))
	defer C.free(unsafe.Pointer(buf))

	cptr := C.pcap_create(dev, buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr:     cptr,
		sampling: 1,
	}, nil
}

// SetBufferSize sets buffer size (in bytes) on the activated handle.
func (p *Pcap) SetBufferSize(sz int32) error {
	if C.pcap_set_buffer_size(p.cptr, C.int(sz)) != 0 {
		return p.Geterror()
	}
	return nil
}

// SetPromisc sets promiscuous mode on the handle. It should be called before
// activation.
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

// SetSnapLen TODO
func (p *Pcap) SetSnapLen(s int32) error {
	if C.pcap_set_snaplen(p.cptr, C.int(s)) != 0 {
		return p.Geterror()
	}
	return nil
}

// SetReadTimeout (milliseconds) that will be used on a capture handle when it
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
func OpenLive(device string, snaplen int32, promisc bool, timeoutMS int32) (*Pcap, error) {
	buf := (*C.char)(C.calloc(errbufSize, 1))
	defer C.free(unsafe.Pointer(buf))

	dev := C.CString(device)
	defer C.free(unsafe.Pointer(dev))

	pro := int32(0)
	if promisc {
		pro = 1
	}

	cptr := C.pcap_open_live(dev, C.int(snaplen), C.int(pro), C.int(timeoutMS), buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr:     cptr,
		sampling: 1,
	}, nil
}

// OpenOffline provides a Pcap over a .pcap file.
func OpenOffline(file string) (*Pcap, error) {
	buf := (*C.char)(C.calloc(errbufSize, 1))
	defer C.free(unsafe.Pointer(buf))

	cf := C.CString(file)
	defer C.free(unsafe.Pointer(cf))

	cptr := C.pcap_open_offline(cf, buf)
	if cptr == nil {
		return nil, &pcapError{C.GoString(buf)}
	}

	return &Pcap{
		cptr:     cptr,
		sampling: 1,
	}, nil
}

// Close calls pcap_close on the underlying pcap_t.
func (p *Pcap) Close() {
	C.pcap_close(p.cptr)
}

// SetSampling sets the sample rate of the handle. We perform sampling in the
// Go wrapper library, as efficiently as we can at that layer.
func (p *Pcap) SetSampling(rate float64) {
	// Take 1 packet every N (approximate).
	//  rate=0.50 sampling=1.0/0.50=2
	//  rate=0.33 sampling=1.0/0.33=3
	//  rate=0.15 sampling=1.0/0.15=6.66=6 (alas)
	p.sampling = int(1.0 / rate)
}

// NextEx gets the next packet on the handle.
func (p *Pcap) NextEx() (*Packet, int32) {
	var pkthdr *C.struct_pcap_pkthdr
	var bufPtr *C.u_char
	var result int32
	for i := 0; i < p.sampling; i++ {
		// "The struct pcap_pkthdr and the packet data are not to be freed by
		// the caller, and are not guaranteed to be valid after the next call
		// ... if the code needs them to remain valid, it must make a copy of
		// them." --pcap_next_ex(3)
		//
		// I believe this is not a terrible way to do sampling. We still incur
		// the cost of pcap_next_ex, which does copy from kernel to userspace,
		// but we skip any further allocations and a lot of analysis in our
		// client code.
		result = int32(C.pcap_next_ex(p.cptr, &pkthdr, &bufPtr))
	}

	buf := unsafe.Pointer(bufPtr)
	if buf == nil {
		return nil, result
	}

	pkt := &Packet{
		Time:   time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)),
		Caplen: uint32(pkthdr.caplen),
		Len:    uint32(pkthdr.len),
		Data:   C.GoBytes(buf, C.int(pkthdr.caplen)),
	}
	return pkt, result
}

// Getstats TODO
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

// SetFilter TODO
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

// SetDatalink TODO
func (p *Pcap) SetDatalink(dlt int) error {
	if C.pcap_set_datalink(p.cptr, C.int(dlt)) == -1 {
		return p.Geterror()
	}
	return nil
}

// DatalinkValueToName string
func DatalinkValueToName(dlt int) string {
	if name := C.pcap_datalink_val_to_name(C.int(dlt)); name != nil {
		return C.GoString(name)
	}
	return ""
}

// DatalinkValueToDescription TODO
func DatalinkValueToDescription(dlt int) string {
	if desc := C.pcap_datalink_val_to_description(C.int(dlt)); desc != nil {
		return C.GoString(desc)
	}
	return ""
}

// FindAllDevs TODO
func FindAllDevs() ([]Interface, error) {
	buf := (*C.char)(C.calloc(errbufSize, 1))
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
