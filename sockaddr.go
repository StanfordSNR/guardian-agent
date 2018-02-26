package guardianagent

// Copied from package syscall

import (
	"syscall"
	"unsafe"
)

func RawSockAddrAnyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrUnix)
		n, err := getLen(pp)
		if err != nil {
			return nil, err
		}
		bytes := (*[len(pp.Path)]byte)(unsafe.Pointer(&pp.Path[0]))
		sa.Name = string(bytes[0:n])
		return sa, nil

	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return anyToSockaddrOS(rsa)
}

func anyToSockaddrOS(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_NETLINK:
		pp := (*syscall.RawSockaddrNetlink)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrNetlink)
		sa.Family = pp.Family
		sa.Pad = pp.Pad
		sa.Pid = pp.Pid
		sa.Groups = pp.Groups
		return sa, nil

	case syscall.AF_PACKET:
		pp := (*syscall.RawSockaddrLinklayer)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrLinklayer)
		sa.Protocol = pp.Protocol
		sa.Ifindex = int(pp.Ifindex)
		sa.Hatype = pp.Hatype
		sa.Pkttype = pp.Pkttype
		sa.Halen = pp.Halen
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, syscall.EAFNOSUPPORT
}

func getLen(sa *syscall.RawSockaddrUnix) (int, error) {
	if sa.Path[0] == 0 {
		// "Abstract" Unix domain socket.
		// Rewrite leading NUL as @ for textual display.
		// (This is the standard convention.)
		// Not friendly to overwrite in place,
		// but the callers below don't care.
		sa.Path[0] = '@'
	}

	// Assume path ends at NUL.
	// This is not technically the GNU/Linux semantics for
	// abstract Unix domain sockets--they are supposed
	// to be uninterpreted fixed-size binary blobs--but
	// everyone uses this convention.
	n := 0
	for n < len(sa.Path) && sa.Path[n] != 0 {
		n++
	}

	return n, nil
}
