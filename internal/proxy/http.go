package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"

	"tr-proxy/internal/netutil"
)

type clientAddrKey struct{}

// ServeHTTP accepts HTTP proxy clients on ln until ln is closed. It handles
// CONNECT tunnels and plain-HTTP requests with an absolute URL.
func (s *Server) ServeHTTP(ctx context.Context, ln net.Listener) {
	// One upstream connection per forwarded request: every request is routed
	// on its own, and connections are not shared between clients.
	transport := &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, err
			}
			client, _ := dctx.Value(clientAddrKey{}).(string)
			up, tracked, err := s.connect(dctx, client, host, port)
			if err != nil {
				return nil, err
			}
			// net/http moves the bytes of a forwarded request, so the idle
			// timeout is put on the connection itself.
			return &trackedConn{Conn: &netutil.IdleConn{Conn: up, Idle: s.idle()}, tracked: tracked}, nil
		},
		ResponseHeaderTimeout: 2 * time.Minute,
	}
	forward := &httputil.ReverseProxy{
		// The outgoing request already carries the absolute URL; forward it
		// unchanged and add no X-Forwarded-* headers. ReverseProxy drops
		// query parameters it cannot parse (such as "a=1;b=2") before
		// Rewrite; the query goes on as the client sent it.
		Rewrite:      func(pr *httputil.ProxyRequest) { pr.Out.URL.RawQuery = pr.In.URL.RawQuery },
		Transport:    transport,
		ErrorLog:     log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) { httpError(w, err) },
	}

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.Auth != nil && !s.httpAuthorized(r) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="tr-proxy"`)
				http.Error(w, "Proxy authentication required.", http.StatusProxyAuthRequired)
				return
			}
			switch {
			case r.Method == http.MethodConnect:
				s.handleConnect(ctx, w, r)
			case r.URL.IsAbs() && r.URL.Scheme == "http" && r.URL.Host != "":
				r.Header.Del("Proxy-Authorization")
				r.Header.Del("Proxy-Connection")
				forward.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientAddrKey{}, r.RemoteAddr)))
			default:
				http.Error(w, "This is a proxy; send CONNECT or a request with an absolute http:// URL.", http.StatusBadRequest)
			}
		}),
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	srv.Serve(ln)
	// The listener is closed: its config changed (users removed, for
	// example) or tr-proxy stops. Requests on kept-alive connections must
	// not go on with the old settings, so idle connections are closed now
	// and active ones after their current request. CONNECT tunnels are
	// hijacked and not affected.
	go func() {
		srv.Shutdown(context.Background())
		transport.CloseIdleConnections()
	}()
}

// httpAuthorized checks the Proxy-Authorization header. A request without
// credentials is not counted as a failed login: clients routinely ask first
// and authenticate on the 407.
func (s *Server) httpAuthorized(r *http.Request) bool {
	scheme, cred, _ := strings.Cut(r.Header.Get("Proxy-Authorization"), " ")
	if !strings.EqualFold(scheme, "Basic") || cred == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(raw), ":")
	return ok && s.authenticate(r.RemoteAddr, username, password)
}

func (s *Server) handleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host, portStr, err := net.SplitHostPort(r.Host)
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || host == "" || port < 1 || port > 65535 {
		http.Error(w, "CONNECT needs host:port", http.StatusBadRequest)
		return
	}

	up, tracked, err := s.connect(ctx, r.RemoteAddr, host, port)
	if err != nil {
		httpError(w, err)
		return
	}
	defer tracked.Done()
	defer up.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot tunnel on this connection", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	client.SetDeadline(time.Time{})

	// Answer in the client's HTTP version. Some clients that send
	// "CONNECT ... HTTP/1.0", macOS nc among them (and with it ssh's
	// ProxyCommand), take only an "HTTP/1.0 200" line for success.
	status := "HTTP/1.1 200 Connection established\r\n\r\n"
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		status = "HTTP/1.0 200 Connection established\r\n\r\n"
	}
	if _, err := buf.WriteString(status); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
	// Bytes the client sent right behind the CONNECT request are already in
	// the server's buffer; pass them on first.
	if n := buf.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(up, buf.Reader, int64(n)); err != nil {
			return
		}
	}
	netutil.Relay(client, up, s.idle())
}

// httpError maps a connect failure to a proxy response.
func httpError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBadDestination):
		http.Error(w, "Not a valid destination host.", http.StatusBadRequest)
	case errors.Is(err, ErrBlocked):
		http.Error(w, "Blocked by proxy rule.", http.StatusForbidden)
	case errors.Is(err, ErrUnavailable):
		http.Error(w, "No healthy route for this destination.", http.StatusServiceUnavailable)
	default:
		http.Error(w, "Proxy could not reach the destination.", http.StatusBadGateway)
	}
}

// trackedConn ends its tracker entry when the connection is closed.
type trackedConn struct {
	net.Conn
	tracked *Tracked
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(c.tracked.Done)
	return c.Conn.Close()
}
