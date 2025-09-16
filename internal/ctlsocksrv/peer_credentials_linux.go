//go:build linux

package ctlsocksrv

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// getPeerCredentials retrieves the credentials of the peer connected to the Unix socket on Linux
func getPeerCredentials(conn *net.UnixConn) (*PeerCredentials, error) {
	// Get the file descriptor
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fd := int(file.Fd())

	// Use SO_PEERCRED to get peer credentials
	var cred syscall.Ucred
	credSize := unsafe.Sizeof(cred)

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		syscall.SOL_SOCKET,
		syscall.SO_PEERCRED,
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&credSize)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_PEERCRED failed: %v", errno)
	}

	return &PeerCredentials{
		UID: int(cred.Uid),
		GID: int(cred.Gid),
		PID: int(cred.Pid),
	}, nil
}
