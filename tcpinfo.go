//go:build linux
// +build linux

package tcpinfo

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

type TCPInfo syscall.TCPInfo

type tlsConn interface {
	NetConn() net.Conn
}

// 支持 net.tcpConn, tls.Conn 底层是net.TCPConn
func GetTCPInfo(conn net.Conn) (*TCPInfo, error) {
	if t, ok := conn.(tlsConn); ok {
		conn = t.NetConn()
	}
	switch t := conn.(type) {
	case *net.TCPConn:
		return GetsockoptTCPInfo(t)
	default:
		return nil, fmt.Errorf("unsupport conn type %T", t)
	}
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
