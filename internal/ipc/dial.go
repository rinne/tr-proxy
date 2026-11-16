package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// The dial protocol on a worker's unix socket: the supervisor connects,
// sends one DialRequest as a JSON line, and reads one DialResponse as a JSON
// line. After a response without an error the connection carries the raw
// byte stream to the destination.

const (
	// DialTimeout bounds name resolution plus connect inside the tunnel.
	DialTimeout = 30 * time.Second

	maxLine = 4096
)

type DialRequest struct {
	Host string `json:"host"` // hostname or IP address
	Port int    `json:"port"`
}

type DialResponse struct {
	Error string `json:"error,omitempty"`
}

// readLine reads up to a newline one byte at a time, so it never consumes
// bytes that belong to the stream after the line.
func readLine(r io.Reader) ([]byte, error) {
	var line []byte
	var b [1]byte
	for len(line) < maxLine {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		if b[0] == '\n' {
			return line, nil
		}
		line = append(line, b[0])
	}
	return nil, errors.New("line too long")
}

func writeLine(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(data, '\n'))
	return err
}

// ReadRequest is the worker's side: read the request.
func ReadRequest(c net.Conn) (DialRequest, error) {
	var req DialRequest
	line, err := readLine(c)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return req, err
	}
	if req.Host == "" || req.Port < 1 || req.Port > 65535 {
		return req, errors.New("bad dial request")
	}
	return req, nil
}

// WriteResponse is the worker's side: report the dial result.
func WriteResponse(c net.Conn, dialErr error) error {
	var resp DialResponse
	if dialErr != nil {
		resp.Error = dialErr.Error()
	}
	return writeLine(c, resp)
}

// Dial is the supervisor's side: ask the worker behind socket to connect to
// host:port through its tunnel. The returned connection is the stream to the
// destination.
func Dial(ctx context.Context, socket, host string, port int) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, fmt.Errorf("worker not reachable: %w", err)
	}

	// Honour ctx while waiting for the worker's answer.
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()

	if err := writeLine(c, DialRequest{Host: host, Port: port}); err != nil {
		c.Close()
		return nil, err
	}
	line, err := readLine(c)
	if err != nil {
		c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("worker closed the connection: %w", err)
	}
	var resp DialResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		c.Close()
		return nil, err
	}
	if resp.Error != "" {
		c.Close()
		return nil, errors.New(resp.Error)
	}
	if !stop() {
		// ctx fired between the answer and here; the deadline is poisoned.
		c.Close()
		return nil, ctx.Err()
	}
	return c, nil
}
