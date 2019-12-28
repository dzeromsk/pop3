package pop3

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/textproto"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	POP3User       = "USER"
	POP3Pass       = "PASS"
	POP3StartTLS   = "STLS"
	POP3Capability = "CAPA"
	POP3Status     = "STAT"
	POP3List       = "LIST"
	POP3UIDList    = "UIDL"
	POP3Retrieve   = "RETR"
	POP3Delete     = "DELE"
	POP3Noop       = "NOOP"
	POP3Reset      = "RSET"
	POP3Quit       = "QUIT"
)

var (
	ErrInvalidAuthorizer = errors.New("pop3: Missing authorizer")
	ErrServerClosed      = errors.New("pop3: Server closed")
)

// Authorizer responds to a POP3 AUTHORIZATION state request.
type Authorizer interface {
	Auth(user, pass string) (Maildropper, error)
}

// Maildropper responds to a POP3 TRANSACTION state requests.
type Maildropper interface {
	List() (size map[string]int, err error)
	Get(key string, message io.Writer) (err error)
	Delete(key string) (err error)
}

// ListenAndServe always returns a non-nil error.
func ListenAndServe(addr string, auth Authorizer) error {
	server := &Server{Addr: addr, Auth: auth}
	return server.ListenAndServe()
}

// ListenAndServeTLS acts identically to ListenAndServe, except that it
// expects POP3S connections. Additionally, files containing a certificate and
// matching private key for the server must be provided.
func ListenAndServeTLS(addr, certFile, keyFile string, auth Authorizer) error {
	server := &Server{Addr: addr, Auth: auth}
	return server.ListenAndServeTLS(certFile, keyFile)
}

// A Server defines parameters for running an POP3 server.
// The zero value for Server is a valid configuration.
type Server struct {
	Addr string // TCP address to listen on, ":pop3" if empty
	Auth Authorizer

	// TLSConfig optionally provides a TLS configuration for use
	// by ServeTLS and ListenAndServeTLS. Note that this value is
	// cloned by ServeTLS and ListenAndServeTLS, so it's not
	// possible to modify the configuration with methods like
	// tls.Config.SetSessionTicketKeys. To use
	// SetSessionTicketKeys, use Server.Serve with a TLS Listener
	// instead.
	TLSConfig *tls.Config

	// ErrorLog specifies an optional logger for errors accepting
	// connections, unexpected behavior from handlers, and
	// underlying FileSystem errors.
	// If nil, logging is done via the log package's standard logger.
	ErrorLog *log.Logger

	inShutdown int32 // accessed atomically (non-zero means we're in Shutdown)
	mu         sync.Mutex
	listeners  map[*net.Listener]struct{}
	activeConn map[*conn]struct{}
	doneChan   chan struct{}
}

// ListenAndServe always returns a non-nil error. After Shutdown or Close,
// the returned error is ErrServerClosed.
func (srv *Server) ListenAndServe() error {
	if srv.shuttingDown() {
		return ErrServerClosed
	}
	if srv.Auth == nil {
		return ErrInvalidAuthorizer
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":pop3"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// ListenAndServeTLS listens on the TCP network address srv.Addr and
// then calls ServeTLS to handle requests on incoming TLS connections.
// Accepted connections are configured to enable TCP keep-alives.
//
// Filenames containing a certificate and matching private key for the
// server must be provided if neither the Server's TLSConfig.Certificates
// nor TLSConfig.GetCertificate are populated. If the certificate is
// signed by a certificate authority, the certFile should be the
// concatenation of the server's certificate, any intermediates, and
// the CA's certificate.
func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	if srv.shuttingDown() {
		return ErrServerClosed
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":pop3s"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer ln.Close()

	return srv.ServeTLS(ln, certFile, keyFile)
}

// Serve accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines read requests and
// then call srv.Handler to reply to them.
//
// Serve always returns a non-nil error and closes l.
// After Shutdown or Close, the returned error is ErrServerClosed.
func (srv *Server) Serve(l net.Listener) error {
	if !srv.trackListener(&l, true) {
		return ErrServerClosed
	}
	defer srv.trackListener(&l, false)

	var tempDelay time.Duration // how long to sleep on accept Err
	for {
		rw, e := l.Accept()
		if e != nil {
			select {
			case <-srv.getDoneChan():
				return ErrServerClosed
			default:
			}
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.logf("pop3: Accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		c := srv.newConn(rw)
		connCtx := context.Background()
		go c.serve(connCtx)
	}
}

// ServeTLS accepts incoming connections on the Listener l, creating a
// new service goroutine for each. The service goroutines perform TLS
// setup and then read requests, calling srv.Handler to reply to them.
//
// Files containing a certificate and matching private key for the
// server must be provided if neither the Server's
// TLSConfig.Certificates nor TLSConfig.GetCertificate are populated.
// If the certificate is signed by a certificate authority, the
// certFile should be the concatenation of the server's certificate,
// any intermediates, and the CA's certificate.
//
// ServeTLS always returns a non-nil error. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		config = srv.TLSConfig.Clone()
	}

	configHasCert := len(config.Certificates) > 0 || config.GetCertificate != nil
	if !configHasCert || certFile != "" || keyFile != "" {
		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
	}

	tlsListener := tls.NewListener(l, config)
	return srv.Serve(tlsListener)
}

func (srv *Server) shuttingDown() bool {
	// TODO: replace inShutdown with the existing atomicBool type;
	// see https://github.com/golang/go/issues/20239#issuecomment-381434582
	return atomic.LoadInt32(&srv.inShutdown) != 0
}

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by srv.mu.
		close(ch)
	}
}

// Close immediately closes all active net.Listeners and any
// connections in state StateNew, StateActive, or StateIdle. For a
// graceful shutdown, use Shutdown.
//
// Close does not attempt to close (and does not even know about)
// any hijacked connections, such as WebSockets.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	atomic.StoreInt32(&srv.inShutdown, 1)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.closeDoneChanLocked()
	err := srv.closeListenersLocked()
	for c := range srv.activeConn {
		c.rwc.Close()
		delete(srv.activeConn, c)
	}
	return err
}

func (srv *Server) logf(format string, args ...interface{}) {
	if srv.ErrorLog != nil {
		srv.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (srv *Server) closeListenersLocked() error {
	var err error
	for ln := range srv.listeners {
		if cerr := (*ln).Close(); cerr != nil && err == nil {
			err = cerr
		}
		delete(srv.listeners, ln)
	}
	return err
}

// Create new connection from rwc.
func (srv *Server) newConn(rwc net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
		text:   textproto.NewConn(rwc),
	}

	if srv.TLSConfig != nil {
		c.TLSConfig = srv.TLSConfig.Clone()
	}

	return c
}

// trackListener adds or removes a net.Listener to the set of tracked
// listeners.
//
// We store a pointer to interface in the map set, in case the
// net.Listener is not comparable. This is safe because we only call
// trackListener via Serve and can track+defer untrack the same
// pointer to local variable there. We never need to compare a
// Listener from another caller.
//
// It reports whether the server is still up (not Shutdown or Closed).
func (srv *Server) trackListener(ln *net.Listener, add bool) bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.listeners == nil {
		srv.listeners = make(map[*net.Listener]struct{})
	}
	if add {
		if srv.shuttingDown() {
			return false
		}
		srv.listeners[ln] = struct{}{}
	} else {
		delete(srv.listeners, ln)
	}
	return true
}

func (srv *Server) trackConn(c *conn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.activeConn == nil {
		srv.activeConn = make(map[*conn]struct{})
	}
	if add {
		srv.activeConn[c] = struct{}{}
	} else {
		delete(srv.activeConn, c)
	}
}

// A conn represents the server side of an POP3 connection.
type conn struct {
	// server is the server on which the connection arrived.
	// Immutable; never nil.
	server *Server

	// rwc is the underlying network connection.
	// This is never wrapped by other types and is the value given out
	// to CloseNotifier callers. It is usually of type *net.TCPConn or
	// *tls.Conn.
	rwc net.Conn

	// text is the textproto.Conn used by the Client.
	text *textproto.Conn

	// TLSConfig is the tls.Config used by the connection.
	TLSConfig *tls.Config

	cmd string
	arg string

	err error // Sticky error.
}

// Serve a new connection.
func (c *conn) serve(ctx context.Context) {
	c.server.trackConn(c, true)
	defer func() {
		if err := recover(); err != nil /* &&  err != ErrAbortHandler */ {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.logf("pop3: panic serving %s: %v\n%s", c.rwc.RemoteAddr(), err, buf)
		}
		c.close()
		c.server.trackConn(c, false)
	}()

	// +OK Gpop ready for requests from 89.64.10.226 v14mb24979864ljv
	c.Ok("Gpop ready for requests from %s %p", c.rwc.RemoteAddr(), c)

	// start state machine
	if err := c.auth(c.server.Auth); err != nil {
		if err != io.EOF {
			c.logf("pop3: Protocol error from %s: %v", c.rwc.RemoteAddr(), err)
		}
		return
	}
}

func (c *conn) logf(format string, args ...interface{}) {
	c.server.logf(format, args...)
}

// Close the connection.
func (c *conn) close() {
	c.rwc.Close()
}

// setErr records the first error encountered.
func (c *conn) setErr(err error) {
	if c.err == nil || c.err == io.EOF {
		c.err = err
	}
}

// debugConnections controls whether all server connections are wrapped
// with a verbose logging wrapper.
const debugConnections = false

func (c *conn) scan() bool {
	if c.err != nil {
		return false
	}

	l, err := c.text.ReadLine()
	if err != nil {
		c.setErr(err)
		return false
	}

	if debugConnections {
		fmt.Println("C:", l)
	}

	part := strings.SplitN(l, " ", 2)
	c.cmd = strings.ToUpper(part[0])
	c.arg = ""
	if len(part) > 1 {
		c.arg = part[1]
	}

	return true
}

func (c *conn) send(format string, args ...interface{}) {
	if debugConnections {
		fmt.Printf("S: "+format+"\n", args...)
	}

	if err := c.text.PrintfLine(format, args...); err != nil {
		c.setErr(err)
	}
}

func (c *conn) Ok(format string, args ...interface{}) {
	c.send("+OK "+format, args...)
}

func (c *conn) Err(format string, args ...interface{}) {
	c.send("-ERR "+format, args...)
}

func (c *conn) auth(auth Authorizer) error {
	var user string
	var pass string

	for c.scan() {
		switch c.cmd {
		case POP3User, POP3Pass:
			switch c.cmd {
			case POP3User:
				user = c.arg
			case POP3Pass:
				pass = c.arg
			}

			if user != "" && pass != "" {
				m, err := auth.Auth(user, pass)
				if err != nil {
					c.Err("invalid password")
					continue
				}
				return c.process(m)
			}

			c.Ok("send PASS")

		case POP3StartTLS:
			if c.TLSConfig == nil {
				c.logf("pop3: startls missing tls config %s", c.rwc.RemoteAddr())
				c.Err("malformed command")
				return nil
			}

			c.rwc = tls.Server(c.rwc, c.TLSConfig)
			c.text = textproto.NewConn(c.rwc)
			c.Ok("Begin TLS negotiation")

		case POP3Capability:
			c.Ok("Capability list follows")
			for _, cap := range []string{
				"USER",
				"STLS",
				"IMPLEMENTATION go-pop3",
			} {
				c.send(cap)
			}
			c.send(".")

		case POP3Quit:
			return c.quit()

		default:
			c.Err("malformed command")
		}
	}

	return c.err
}

type hash string

func (c *conn) process(maildrop Maildropper) error {
	var total int               // total messages size
	size := make(map[hash]int)  // mapping from hash to size
	index := make(map[int]hash) // mapping from temporary numeric id to hash
	// set of messages marked for deleteion
	deleted := make(map[int]struct{})

	sizes, err := maildrop.List()
	if err != nil {
		c.Err("maildrop locked")
		return err
	}

	var keys []string
	for k := range sizes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// TODO(dzeromsk): simplify after adding sorted keys, remove deletes,
	// use index etc.
	for n, k := range keys {
		index[n+1] = hash(k)
		size[hash(k)] = sizes[k]
		total += sizes[k]
	}

	c.Ok("welcome home")

	for c.scan() {
		switch c.cmd {
		case POP3Noop:
			c.Ok("")

		case POP3Status:
			c.Ok("%d %d", len(size), total)

		case POP3List, POP3UIDList:
			if c.arg == "" {
				c.Ok("%d messages (%d octets)", len(size), total)
				switch c.cmd {
				case POP3List:
					for n, v := range keys {
						if _, ok := deleted[n+1]; !ok {
							c.send("%d %d", n+1, size[hash(v)])
						}
					}

				case POP3UIDList:
					for k, v := range index {
						if _, ok := deleted[k]; !ok {
							c.send("%d %s", k, v)
						}
					}
				}
				c.send(".")
				continue
			}

			n, err := strconv.Atoi(c.arg)
			if err != nil {
				c.Err("invalid argument")
				continue
			}
			switch c.cmd {
			case POP3List:
				c.Ok("%d %d", n, size[index[n]])
				continue

			case POP3UIDList:
				c.Ok("%d %s", n, index[n])
				continue
			}

		case POP3Retrieve:
			n, err := strconv.Atoi(c.arg)
			if err != nil {
				c.Err("invalid argument")
				continue
			}
			h, ok := index[n]
			if !ok {
				c.Err("unknown message")
				continue
			}
			var buf bytes.Buffer
			if err := maildrop.Get(string(h), &buf); err != nil {
				c.Err("no such message")
				continue
			}
			c.Ok("%d octets", buf.Len())
			w := c.text.DotWriter()
			buf.WriteTo(w)
			w.Close()

		case POP3Delete:
			n, err := strconv.Atoi(c.arg)
			if err != nil {
				c.Err("invalid argument")
				continue
			}
			if _, ok := index[n]; !ok {
				c.Err("unknown message")
				continue
			}
			deleted[n] = struct{}{}
			c.Ok("message %d deleted", n)

		case POP3Reset:
			n, err := strconv.Atoi(c.arg)
			if err != nil {
				c.Err("invalid argument")
				continue
			}
			if _, ok := deleted[n]; !ok {
				c.Err("RSET _what_?")
				continue
			}
			delete(deleted, n)
			c.Ok("")

		case POP3Quit:
			var err error
			for k := range deleted {
				err2 := maildrop.Delete(string(index[k]))
				if err2 != nil {
					err = err2
				}
			}
			if err != nil {
				c.Err("oops")
				continue
			}

			return c.quit()

		default:
			c.Err("malformed command")
		}
	}

	return c.err
}

func (c *conn) quit() error {
	c.Ok("bye")
	return nil
}
