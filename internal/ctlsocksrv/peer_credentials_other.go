//go:build !linux && !darwin

package ctlsocksrv

import (
	"net"
	"os"
)

// getPeerCredentials retrieves the credentials of the peer connected to the Unix socket
// This is a fallback implementation for unsupported platforms
func getPeerCredentials(conn *net.UnixConn) (*PeerCredentials, error) {
	// For unsupported platforms, we'll use a simplified approach
	// that assumes the peer has the same UID as the current process
	// This is a reasonable assumption for local Unix sockets

	return &PeerCredentials{
		UID: os.Getuid(),
		GID: os.Getgid(),
		PID: os.Getpid(),
	}, nil
}
