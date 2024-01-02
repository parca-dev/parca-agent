// Copyright 2023-2024 The Parca Authors
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

package systemd

import (
	"time"
)

const (
	// DefaultConnectionTimeout is the default
	// read/write timeout associated with the connection.
	DefaultConnectionTimeout = time.Second
	// DefaultConnectionReadSize is the default size (in bytes)
	// of the buffer which is used for reading from a connection.
	// Buffering reduces count of read syscalls,
	// e.g., ListUnits makes 12 read syscalls when decoding 35KB message
	// using 4KB buffer.
	// It takes over 4K syscalls without buffering to decode the same message.
	DefaultConnectionReadSize = 4096
	// DefaultStringConverterSize is the default buffer size (in bytes)
	// of the string converter that is used to convert bytes to strings
	// with less allocs.
	//
	// After trying various buffer sizes on ListUnits,
	// a 4KB buffer showed 24.96 KB/op and 7 allocs/op
	// in a benchmark when decoding 35KB message.
	DefaultStringConverterSize = 4096
)

// Config represents a Client config.
type Config struct {
	// busAddr is a bus address, for example,
	// unix:path=/var/run/dbus/system_bus_socket.
	busAddr string
	// connTimeout is a connection timeout set with SetDeadline.
	connTimeout time.Duration
	// connReadSize defines the length of a buffer to read from
	// a D-Bus connection.
	connReadSize int
	// strConvSize defines the length of a buffer of a string converter.
	strConvSize int
	// isSerialCheckEnabled when set will check whether message serials match.
	isSerialCheckEnabled bool
}

// Option sets up a Config.
type Option func(*Config)

// WithAddress sets a bus address.
func WithAddress(addr string) Option {
	return func(c *Config) {
		c.busAddr = addr
	}
}

// WithTimeout sets the read and write timeouts associated
// with the connection.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.connTimeout = timeout
	}
}

// WithConnectionReadSize sets a size of a buffer
// which is used for reading from a D-Bus connection.
// Bigger the buffer, less read syscalls will be made.
func WithConnectionReadSize(size int) Option {
	return func(c *Config) {
		c.connReadSize = size
	}
}

// WithStringConverterSize sets a buffer size of the string converter
// to reduce allocs.
func WithStringConverterSize(size int) Option {
	return func(c *Config) {
		c.strConvSize = size
	}
}

// WithSerialCheck enables checking of message serials,
// i.e., the Client will compare the serial number sent within a message to D-Bus
// with the serial received in the reply.
//
// Note, this requires decoding of header fields which incurs extra allocs.
// There shouldn't be any request/reply mishmash because
// the Client guarantees that the underlying D-Bus connection is accessed sequentially.
func WithSerialCheck() Option {
	return func(c *Config) {
		c.isSerialCheckEnabled = true
	}
}
