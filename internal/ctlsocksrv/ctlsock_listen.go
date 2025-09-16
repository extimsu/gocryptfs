package ctlsocksrv

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// cleanupOrphanedSocket deletes an orphaned socket file at `path`.
// The file at `path` will only be deleted if:
// 1) It is a socket file
// 2) Connecting to it results in ECONNREFUSED
func cleanupOrphanedSocket(path string) {
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		// This socket file is still active. Don't delete it.
		conn.Close()
		return
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		tlog.Info.Printf("ctlsock: deleting orphaned socket file %q\n", path)
		err = os.Remove(path)
		if err != nil {
			tlog.Warn.Printf("ctlsock: deleting socket file failed: %v", path)
		}
	}
}

func Listen(path string) (net.Listener, error) {
	cleanupOrphanedSocket(path)

	// Create parent directory with secure permissions (0700) if it doesn't exist
	parentDir := filepath.Dir(path)
	if err := os.MkdirAll(parentDir, 0700); err != nil {
		return nil, err
	}

	// Create the listener
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}

	// Set secure permissions on the socket file (0600)
	if err := os.Chmod(path, 0600); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, err
	}

	// Ensure parent directory permissions are secure (0700)
	if err := os.Chmod(parentDir, 0700); err != nil {
		tlog.Warn.Printf("ctlsock: failed to secure parent directory permissions: %v", err)
	}

	return listener, nil
}
