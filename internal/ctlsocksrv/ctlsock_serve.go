// Package ctlsocksrv implements the control socket interface that can be
// activated by passing "-ctlsock" on the command line.
package ctlsocksrv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Interface should be implemented by fusefrontend[_reverse]
type Interface interface {
	EncryptPath(string) (string, error)
	DecryptPath(string) (string, error)
}

type ctlSockHandler struct {
	fs     Interface
	socket *net.UnixListener
	// Rate limiting
	rateLimiter map[string]*rateLimitEntry
	rateMutex   sync.RWMutex
}

type rateLimitEntry struct {
	lastRequest  time.Time
	requestCount int
}

// Rate limiting constants
const (
	maxRequestsPerMinute = 60
	rateLimitWindow      = time.Minute
	connectionTimeout    = 30 * time.Second
	readTimeout          = 5 * time.Second
)

// Serve serves incoming connections on "sock". This call blocks so you
// probably want to run it in a new goroutine.
func Serve(sock net.Listener, fs Interface) {
	handler := ctlSockHandler{
		fs:          fs,
		socket:      sock.(*net.UnixListener),
		rateLimiter: make(map[string]*rateLimitEntry),
	}
	handler.acceptLoop()
}

func (ch *ctlSockHandler) acceptLoop() {
	for {
		conn, err := ch.socket.Accept()
		if err != nil {
			// This can trigger on program exit with "use of closed network connection".
			// Special-casing this is hard due to https://github.com/golang/go/issues/4373
			// so just don't use tlog.Warn to not cause panics in the tests.
			tlog.Info.Printf("ctlsock: Accept error: %v", err)
			break
		}
		go ch.handleConnection(conn.(*net.UnixConn))
	}
}

// checkPeerCredentials verifies that the connecting peer has the same UID as the server
func (ch *ctlSockHandler) checkPeerCredentials(conn *net.UnixConn) error {
	// Get peer credentials
	cred, err := getPeerCredentials(conn)
	if err != nil {
		return fmt.Errorf("failed to get peer credentials: %v", err)
	}

	// Get our own UID
	ourUID := os.Getuid()

	// Check if UIDs match
	if cred.UID != ourUID {
		return fmt.Errorf("peer UID %d does not match server UID %d", cred.UID, ourUID)
	}

	return nil
}

// checkRateLimit verifies that the client is not exceeding rate limits
func (ch *ctlSockHandler) checkRateLimit(clientID string) error {
	ch.rateMutex.Lock()
	defer ch.rateMutex.Unlock()

	now := time.Now()
	entry, exists := ch.rateLimiter[clientID]

	if !exists {
		// First request from this client
		ch.rateLimiter[clientID] = &rateLimitEntry{
			lastRequest:  now,
			requestCount: 1,
		}
		return nil
	}

	// Check if we're still within the rate limit window
	if now.Sub(entry.lastRequest) > rateLimitWindow {
		// Reset the counter
		entry.lastRequest = now
		entry.requestCount = 1
		return nil
	}

	// Check if we've exceeded the rate limit
	if entry.requestCount >= maxRequestsPerMinute {
		return fmt.Errorf("rate limit exceeded: %d requests per minute", maxRequestsPerMinute)
	}

	// Increment the counter
	entry.requestCount++
	entry.lastRequest = now

	return nil
}

// ReadBufSize is the size of the request read buffer.
// The longest possible path is 4096 bytes on Linux and 1024 on Mac OS X so
// 5000 bytes should be enough to hold the whole JSON request. This
// assumes that the path does not contain too many characters that had to be
// be escaped in JSON (for example, a null byte blows up to "\u0000").
// We abort the connection if the request is bigger than this.
const ReadBufSize = 5000

// handleConnection reads and parses JSON requests from "conn"
func (ch *ctlSockHandler) handleConnection(conn *net.UnixConn) {
	defer conn.Close()

	// Set connection timeout
	conn.SetDeadline(time.Now().Add(connectionTimeout))

	// Check peer credentials (same UID requirement)
	if err := ch.checkPeerCredentials(conn); err != nil {
		tlog.Warn.Printf("ctlsock: peer credential check failed: %v", err)
		return
	}

	// Get client identifier for rate limiting
	clientID := getClientIdentifier(conn)

	buf := make([]byte, ReadBufSize)
	for {
		// Set read timeout for each request
		conn.SetReadDeadline(time.Now().Add(readTimeout))

		n, err := conn.Read(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			tlog.Warn.Printf("ctlsock: Read error: %#v", err)
			return
		}
		if n == ReadBufSize {
			tlog.Warn.Printf("ctlsock: request too big (max = %d bytes)", ReadBufSize-1)
			return
		}

		// Check rate limit
		if err := ch.checkRateLimit(clientID); err != nil {
			tlog.Warn.Printf("ctlsock: rate limit exceeded for client %s: %v", clientID, err)
			sendResponse(conn, err, "", "")
			return
		}

		data := buf[:n]
		var in ctlsock.RequestStruct
		err = json.Unmarshal(data, &in)
		if err != nil {
			tlog.Warn.Printf("ctlsock: JSON Unmarshal error: %#v", err)
			err = errors.New("JSON Unmarshal error: " + err.Error())
			sendResponse(conn, err, "", "")
			continue
		}
		ch.handleRequest(&in, conn)
	}
}

// handleRequest handles an already-unmarshaled JSON request
func (ch *ctlSockHandler) handleRequest(in *ctlsock.RequestStruct, conn *net.UnixConn) {
	var err error
	var inPath, outPath, clean, warnText string
	// You cannot perform both decryption and encryption in one request
	if in.DecryptPath != "" && in.EncryptPath != "" {
		err = errors.New("Ambiguous")
		sendResponse(conn, err, "", "")
		return
	}
	// Neither encryption nor encryption has been requested, makes no sense
	if in.DecryptPath == "" && in.EncryptPath == "" {
		err = errors.New("empty input")
		sendResponse(conn, err, "", "")
		return
	}
	// Canonicalize input path
	if in.EncryptPath != "" {
		inPath = in.EncryptPath
	} else {
		inPath = in.DecryptPath
	}
	clean = SanitizePath(inPath)
	// Warn if a non-canonical path was passed
	if inPath != clean {
		warnText = fmt.Sprintf("Non-canonical input path '%s' has been interpreted as '%s'.", inPath, clean)
	}
	// Error out if the canonical path is now empty
	if clean == "" {
		err = errors.New("empty input after canonicalization")
		sendResponse(conn, err, "", warnText)
		return
	}
	// Actual encrypt or decrypt operation
	if in.EncryptPath != "" {
		outPath, err = ch.fs.EncryptPath(clean)
	} else {
		outPath, err = ch.fs.DecryptPath(clean)
	}
	sendResponse(conn, err, outPath, warnText)
}

// sendResponse sends a JSON response message
func sendResponse(conn *net.UnixConn, err error, result string, warnText string) {
	msg := ctlsock.ResponseStruct{
		Result:   result,
		WarnText: warnText,
	}
	if err != nil {
		msg.ErrText = err.Error()
		msg.ErrNo = -1
		// Try to extract the actual error number
		if pe, ok := err.(*os.PathError); ok {
			if se, ok := pe.Err.(syscall.Errno); ok {
				msg.ErrNo = int32(se)
			}
		} else if err == syscall.ENOENT {
			msg.ErrNo = int32(syscall.ENOENT)
		}
	}
	jsonMsg, err := json.Marshal(msg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Marshal failed: %v", err)
		return
	}
	// For convenience for the user, add a newline at the end.
	jsonMsg = append(jsonMsg, '\n')
	_, err = conn.Write(jsonMsg)
	if err != nil {
		tlog.Warn.Printf("ctlsock: Write failed: %v", err)
	}
}

// PeerCredentials represents the credentials of a Unix socket peer
type PeerCredentials struct {
	UID int
	GID int
	PID int
}

// getPeerCredentials is implemented in platform-specific files:
// - peer_credentials_linux.go for Linux
// - peer_credentials_darwin.go for macOS
// - peer_credentials_other.go for other platforms

// getClientIdentifier returns a unique identifier for the client connection
func getClientIdentifier(conn *net.UnixConn) string {
	// Use the remote address as a simple client identifier
	// In a more sophisticated implementation, you might use peer credentials
	remoteAddr := conn.RemoteAddr()
	if remoteAddr != nil {
		return remoteAddr.String()
	}
	return "unknown"
}
