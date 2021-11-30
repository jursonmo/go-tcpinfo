// +build linux

package tcpinfo

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

type TCPInfo syscall.TCPInfo

//支持 net.tcpConn, tls.Conn 底层是net.TCPConn
func GetTCPInfo(conn net.Conn) (*TCPInfo, error) {
	var rawConn syscall.RawConn
	var err error
	switch t := conn.(type) {
	case *net.TCPConn:
		rawConn, err = conn.(*net.TCPConn).SyscallConn()
	case *tls.Conn:
		///usr/local/go/src/crypto/tls/conn.go
		/*
			type Conn struct {
				// constant
				conn    net.Conn
				....
			}
		*/
		type tc struct {
			underConn net.Conn
		}
		tconn := (*tc)(unsafe.Pointer(conn.(*tls.Conn)))
		if tcpConn, ok := tconn.underConn.(*net.TCPConn); ok {
			rawConn, err = tcpConn.SyscallConn()
		} else {
			return nil, errors.New("tls under conn is not *net.TCPConn")
		}
	default:
		return nil, fmt.Errorf("unsupport conn type %+v", t)
	}

	if err != nil || rawConn == nil {
		return nil, err
	}

	tcpInfo := TCPInfo{}
	size := unsafe.Sizeof(tcpInfo)
	var errno syscall.Errno
	err = rawConn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&tcpInfo)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return nil, fmt.Errorf("rawconn control failed. err=%v", err)
	}

	if errno != 0 {
		return nil, fmt.Errorf("syscall failed. errno=%d", errno)
	}

	return &tcpInfo, nil
}

func GetsockoptTCPInfo(tcpConn *net.TCPConn) (*TCPInfo, error) {
	if tcpConn == nil {
		return nil, fmt.Errorf("tcp conn is nil")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("error getting raw connection. err=%v", err)
	}

	tcpInfo := TCPInfo{}
	size := unsafe.Sizeof(tcpInfo)
	var errno syscall.Errno
	err = rawConn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, syscall.SOL_TCP, syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&tcpInfo)), uintptr(unsafe.Pointer(&size)), 0)
	})
	if err != nil {
		return nil, fmt.Errorf("rawconn control failed. err=%v", err)
	}

	if errno != 0 {
		return nil, fmt.Errorf("syscall failed. errno=%d", errno)
	}

	return &tcpInfo, nil
}
