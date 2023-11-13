// Copyright 2023 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package systemd provides access to systemd via D-Bus
// using Unix domain sockets as a transport.
// The objective of this package is to list services
// with a low overhead for a caller.
package systemd

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// dial connects to dbus via a Unix domain socket
// specified by a bus address,
// for example, "unix:path=/run/user/1000/bus".
func dial(busAddr string) (*net.UnixConn, error) {
	prefix := "unix:path="
	if !strings.HasPrefix(busAddr, prefix) {
		return nil, errors.New("dbus address not found")
	}
	path := busAddr[len(prefix):]

	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: path,
		Net:  "unix",
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// New creates a new Client to access systemd via dbus.
//
// By default it connects to the system message bus
// using address found in DBUS_SYSTEM_BUS_ADDRESS environment variable.
// If that variable is not set,
// the Client will try to connect to the well-known address
// unix:path=/var/run/dbus/system_bus_socket, see
// https://dbus.freedesktop.org/doc/dbus-specification.html.
func New(opts ...Option) (*Client, error) {
	conf := Config{
		connTimeout:          DefaultConnectionTimeout,
		connReadSize:         DefaultConnectionReadSize,
		strConvSize:          DefaultStringConverterSize,
		isSerialCheckEnabled: false,
	}
	for _, opt := range opts {
		opt(&conf)
	}

	if conf.busAddr == "" {
		addr := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS")
		if addr == "" {
			addr = "unix:path=/var/run/dbus/system_bus_socket"
		}

		conf.busAddr = addr
	}

	strConv := newStringConverter(conf.strConvSize)
	msgEnc := messageEncoder{
		Enc:  newEncoder(nil),
		Conv: strConv,
	}
	msgDec := messageDecoder{
		Dec:              newDecoder(nil),
		Conv:             strConv,
		SkipHeaderFields: true,
	}
	if conf.isSerialCheckEnabled {
		msgDec.SkipHeaderFields = false
	}

	c := Client{
		conf:    conf,
		conn:    nil,
		bufConn: bufio.NewReaderSize(nil, conf.connReadSize),
		msgEnc:  &msgEnc,
		msgDec:  &msgDec,
	}
	if err := c.Reset(); err != nil {
		return nil, err
	}

	return &c, nil
}

// Client provides access to systemd via dbus.
// A caller shouldn't use Client concurrently.
type Client struct {
	conf Config
	conn *net.UnixConn
	// bufConn buffers the reads from a connection
	// thus reducing count of read syscalls.
	bufConn *bufio.Reader
	msgEnc  *messageEncoder
	msgDec  *messageDecoder

	// connName is a D-Bus connection name returned from Hello method.
	connName string
	// According to https://dbus.freedesktop.org/doc/dbus-specification.html
	// D-Bus connection receives messages serially.
	// The client doesn't have to wait for replies before sending more messages.
	// The client can match the replies with a serial number it included in a request.
	//
	// This Client implementation doesn't allow to call its methods concurrently,
	// because a caller could send multiple messages,
	// and the Client would read message fragments from the same connection.
	mu sync.Mutex
	// The serial of this message,
	// used as a cookie by the sender to identify the reply corresponding to this request.
	// This must not be zero.
	msgSerial uint32
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Reset resets the client forcing it to reconnect,
// perform external auth, and send Hello message.
func (c *Client) Reset() error {
	if !c.mu.TryLock() {
		return errors.New("must be called serially")
	}
	defer c.mu.Unlock()

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return err
		}
	}

	conn, err := dial(c.conf.busAddr)
	if err != nil {
		return err
	}

	err = conn.SetDeadline(time.Now().Add(c.conf.connTimeout))
	if err != nil {
		return fmt.Errorf("dbus set deadline failed: %w", err)
	}

	if err = authExternal(conn); err != nil {
		return fmt.Errorf("dbus auth failed: %w", err)
	}

	c.conn = conn
	c.bufConn.Reset(conn)
	c.connName = ""
	c.msgSerial = 0

	if err = c.hello(); err != nil {
		return fmt.Errorf("dbus Hello failed: %w", err)
	}

	return nil
}

// nextMsgSerial returns the next message number.
// It resets the serial to 1 after overflowing.
func (c *Client) nextMsgSerial() uint32 {
	c.msgSerial++
	// Start over when the serial overflows 4,294,967,295.
	if c.msgSerial == 0 {
		c.msgSerial++
	}
	return c.msgSerial
}

// verifyMsgSerial verifies that the message serial sent
// in the request matches the reply serial found in the header field.
func verifyMsgSerial(h *header, connName string, serial uint32) error {
	for _, f := range h.Fields {
		switch f.Code {
		case fieldReplySerial:
			replySerial := uint32(f.U)
			if serial != replySerial {
				return fmt.Errorf("message reply serial mismatch: want %d got %d", serial, replySerial)
			}
		case fieldDestination:
			if connName != f.S {
				return fmt.Errorf("message connection name mismatch: want %q got %q", connName, f.S)
			}
		}
	}

	return nil
}

// hello obtains a unique connection name, e.g., ":1.47".
//
// Before an application is able to send messages
// to other applications it must send
// the org.freedesktop.DBus.Hello message
// to the message bus to obtain a unique name.
//
// If an application without a unique name
// tries to send a message to another application,
// or a message to the message bus itself
// that isn't the org.freedesktop.DBus.Hello message,
// it will be disconnected from the bus.
func (c *Client) hello() error {
	serial := c.nextMsgSerial()

	err := c.msgEnc.EncodeHello(c.conn, serial)
	if err != nil {
		return fmt.Errorf("encode Hello: %w", err)
	}

	c.connName, err = c.msgDec.DecodeHello(c.bufConn)
	if err != nil {
		return fmt.Errorf("decode Hello: %w", err)
	}

	if c.conf.isSerialCheckEnabled {
		err = verifyMsgSerial(c.msgDec.Header(), c.connName, serial)
	}

	return err
}

// ListUnits fetches systemd units,
// optionally filters them with a given predicate, and calls f.
// The pointer to Unit struct in f must not be retained,
// because its fields change on each f call.
//
// Note, don't call any Client's methods within f,
// because concurrent reading from the same underlying connection
// is not supported.
func (c *Client) ListUnits(p Predicate, f func(*Unit)) error {
	if !c.mu.TryLock() {
		return errors.New("must be called serially")
	}
	defer c.mu.Unlock()

	err := c.conn.SetDeadline(time.Now().Add(c.conf.connTimeout))
	if err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	serial := c.nextMsgSerial()
	// Send a dbus message that calls
	// org.freedesktop.systemd1.Manager.ListUnits method
	// to get an array of all currently loaded systemd units.
	err = c.msgEnc.EncodeListUnits(c.conn, serial)
	if err != nil {
		return fmt.Errorf("encode ListUnits: %w", err)
	}

	err = c.msgDec.DecodeListUnits(c.bufConn, p, f)
	if err != nil {
		return fmt.Errorf("decode ListUnits: %w", err)
	}

	if c.conf.isSerialCheckEnabled {
		err = verifyMsgSerial(c.msgDec.Header(), c.connName, serial)
	}

	return err
}

// MainPID fetches the main PID of the service.
// If a service is inactive (see Unit.ActiveState),
// the returned PID will be zero.
//
// Note, you can't call this method within ListUnits's f func,
// because that would imply concurrent reading from the same underlying connection.
// Simply waiting on a lock won't help, because ListUnits won't be able to
// finish waiting for MainPID, thus creating a deadlock.
func (c *Client) MainPID(service string) (uint32, error) {
	if !c.mu.TryLock() {
		return 0, errors.New("must be called serially")
	}
	defer c.mu.Unlock()

	err := c.conn.SetDeadline(time.Now().Add(c.conf.connTimeout))
	if err != nil {
		return 0, fmt.Errorf("set deadline: %w", err)
	}

	serial := c.nextMsgSerial()
	// Send a dbus message that calls
	// org.freedesktop.DBus.Properties.Get method
	// to retrieve MainPID property from
	// org.freedesktop.systemd1.Service interface.
	err = c.msgEnc.EncodeMainPID(c.conn, service, serial)
	if err != nil {
		return 0, fmt.Errorf("encode MainPID: %w", err)
	}

	var pid uint32
	pid, err = c.msgDec.DecodeMainPID(c.bufConn)
	if err != nil {
		return pid, fmt.Errorf("decode MainPID: %w", err)
	}

	if c.conf.isSerialCheckEnabled {
		err = verifyMsgSerial(c.msgDec.Header(), c.connName, serial)
	}

	return pid, err
}
