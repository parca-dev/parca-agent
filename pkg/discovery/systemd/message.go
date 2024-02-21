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
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// Unit represents a currently loaded systemd unit.
// Note that units may be known by multiple names at the same name,
// and hence there might be more unit names loaded than actual units behind them.
type Unit struct {
	// Name is the primary unit name.
	Name string
	// Description is the human readable description.
	Description string
	// LoadState is the load state, i.e., whether the unit file has been loaded successfully.
	LoadState string
	// ActiveState is the active state, i.e., whether the unit is currently started or not.
	ActiveState string
	// SubState is the sub state, i.e.,
	// a more fine-grained version of the active state that
	// is specific to the unit type, which the active state is not.
	SubState string
	// Followed is a unit that is being followed in its state by this unit,
	// if there is any, otherwise the empty string.
	Followed string
	// Path is the unit object path.
	Path string
	// JobID is the numeric job ID
	// if there is a job queued for the job unit, 0 otherwise.
	JobID uint32
	// JobType is the job type.
	JobType string
	// JobPath is the job object path.
	JobPath string
}

// Predicate is used to filter out a decoded struct
// based on its field index and a value.
// This helps to reduce memory consumption
// because a decoder can ignore the remaining struct fields.
// For example, D-Bus ListUnits returns tens of kilobytes
// in a reply, but a caller is interested only in service units.
//
// The field name would be more convenient to work with
// compared to a field index, but that causes unintended allocs.
type Predicate func(fieldIndex int, value []byte) bool

var svcSuffix = []byte(".service")

// IsService is a predicate that filters systemd services,
// i.e., units whose name (field index 0) ends with ".service".
// For example, "ssh.service".
//
// A benchmark showed ~4.5 less KB/op when decoding 35KB message.
func IsService(fieldIndex int, s []byte) bool {
	switch fieldIndex {
	case 0:
		return bytes.HasSuffix(s, svcSuffix)
	default:
		return true
	}
}

func newMessageDecoder() *messageDecoder {
	return &messageDecoder{
		Dec:              newDecoder(nil),
		Conv:             newStringConverter(DefaultStringConverterSize),
		SkipHeaderFields: true,
	}
}

// messageDecoder is responsible for decoding responses from dbus method calls.
type messageDecoder struct {
	Dec  *decoder
	Conv *stringConverter
	// SkipHeaderFields indicates to the decoder that
	// the header fields shouldn't be decoded thus reducing allocs.
	SkipHeaderFields bool

	// The following fields are reused to reduce memory allocs.
	bodyReader io.LimitedReader
	unit       Unit
	hdr        header
}

// Header returns the recently decoded header
// in case the caller wants to inspect fields such as ReplySerial.
// Make sure that SkipHeaderFields is false,
// otherwise there will be no header fields.
func (d *messageDecoder) Header() *header {
	return &d.hdr
}

// DecodeHello decodes hello reply from systemd
// org.freedesktop.DBus.Hello method
// and returns a connection name, e.g., ":1.47".
func (d *messageDecoder) DecodeHello(conn io.Reader) (string, error) {
	d.Dec.Reset(conn)

	err := decodeHeader(d.Dec, d.Conv, &d.hdr, d.SkipHeaderFields)
	if err != nil {
		return "", fmt.Errorf("message header: %w", err)
	}

	d.bodyReader.R = conn
	d.bodyReader.N = int64(d.hdr.BodyLen)
	d.Dec.Reset(&d.bodyReader)

	// Decode an error reply.
	if d.hdr.Type == msgTypeError {
		s, err := d.Dec.String()
		if err != nil {
			return "", fmt.Errorf("decode error reply: %w", err)
		}
		return "", errors.New(d.Conv.String(s))
	}

	var connName []byte
	if connName, err = d.Dec.String(); err != nil {
		return "", fmt.Errorf("decode connection name: %w", err)
	}

	return d.Conv.String(connName), nil
}

// DecodeListUnits decodes a reply from systemd ListUnits method.
// The pointer to Unit struct in f must not be retained,
// because its fields change on each f call.
func (d *messageDecoder) DecodeListUnits(conn io.Reader, p Predicate, f func(*Unit)) error {
	d.Dec.Reset(conn)

	// Decode the message header (16 bytes).
	//
	// Then read the message header where the body signature is stored.
	// The header usually occupies 61 bytes.
	// Since we already know the signature from the spec,
	// the header is discarded.
	//
	// Note, the length of the header must be a multiple of 8,
	// allowing the body to begin on an 8-byte boundary.
	// If the header does not naturally end on an 8-byte boundary,
	// up to 7 bytes of alignment padding is added.
	err := decodeHeader(d.Dec, d.Conv, &d.hdr, d.SkipHeaderFields)
	if err != nil {
		return fmt.Errorf("message header: %w", err)
	}

	// Read the message body limited by the body length.
	// For example, if it is 35714 bytes,
	// we should stop reading at offset 35794,
	// because the body starts at offset 80,
	// i.e., offset 35794 = 16 head + 61 header + 3 padding + 35714 body.
	d.bodyReader.R = conn
	d.bodyReader.N = int64(d.hdr.BodyLen)
	d.Dec.Reset(&d.bodyReader)

	switch d.hdr.Type {
	// Decode an error reply.
	case msgTypeError:
		s, err := d.Dec.String()
		if err != nil {
			return fmt.Errorf("decode error reply: %w", err)
		}
		return errors.New(d.Conv.String(s))
	// Discard the signal that came before the expected reply,
	// i.e., "name acquired" signal.
	case msgTypeSignal:
		if _, err = d.Dec.ReadN(d.hdr.BodyLen); err != nil {
			return fmt.Errorf("discard signal body: %w", err)
		}
		// Decode the following message.
		return d.DecodeListUnits(conn, p, f)
	}

	// ListUnits has a body signature "a(ssssssouso)" which is
	// ARRAY of STRUCT.
	//
	// Read the body starting from the array length "a" (uint32).
	// The array length is in bytes, e.g., 35706 bytes.
	if _, err = d.Dec.Uint32(); err != nil {
		return fmt.Errorf("discard unit array length: %w", err)
	}

	for {
		err = decodeUnit(d.Dec, d.Conv, p, &d.unit)
		switch err { //nolint:errorlint
		case nil:
			f(&d.unit)
		case errIgnore:
		case io.EOF:
			return nil
		default:
			return fmt.Errorf("message body: %w", err)
		}
	}
}

type sentinelError string

func (e sentinelError) Error() string { return string(e) }

const errIgnore = sentinelError("ignore")

// decodeUnit decodes D-Bus Unit struct.
// A caller can supply a predicate to reduce allocs.
// If a predicate filtered out the struct, the errIgnore is returned.
// In that case the unit would contain unusable data.
//
// Note, despite a predicate, all the struct fields are processed
// to advance the decoder.
func decodeUnit(d *decoder, conv *stringConverter, p Predicate, unit *Unit) error {
	// The "()" symbols in the signature represent a STRUCT
	// which is always aligned to an 8-byte boundary,
	// regardless of the alignments of their contents.
	if err := d.Align(8); err != nil {
		return err
	}

	// The Unit struct's fields represent the signature "ssssssouso".
	// Here we decode all its fields sequentially.
	v := reflect.ValueOf(unit).Elem()
	var ignore bool
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)

		switch field.Kind() { //nolint:exhaustive
		case reflect.String:
			s, err := d.String()
			if err != nil {
				return err
			}

			if p == nil || p(i, s) {
				field.SetString(conv.String(s))
			} else {
				ignore = true
			}

		case reflect.Uint32:
			u, err := d.Uint32()
			if err != nil {
				return err
			}
			field.SetUint(uint64(u))
		}
	}

	// Indicate that a caller must ignore the unit struct
	// because some fields were not decoded due to the predicate.
	if ignore {
		return errIgnore
	}

	return nil
}

// DecodeMainPID decodes MainPID property reply from systemd
// org.freedesktop.DBus.Properties.Get method.
func (d *messageDecoder) DecodeMainPID(conn io.Reader) (uint32, error) {
	d.Dec.Reset(conn)

	err := decodeHeader(d.Dec, d.Conv, &d.hdr, d.SkipHeaderFields)
	if err != nil {
		return 0, fmt.Errorf("message header: %w", err)
	}

	d.bodyReader.R = conn
	d.bodyReader.N = int64(d.hdr.BodyLen)
	d.Dec.Reset(&d.bodyReader)

	switch d.hdr.Type {
	// Decode an error reply, e.g., invalid unit name.
	case msgTypeError:
		s, err := d.Dec.String()
		if err != nil {
			return 0, fmt.Errorf("decode error reply: %w", err)
		}
		return 0, errors.New(d.Conv.String(s))
	// Discard the signal that came before the expected reply,
	// i.e., "name acquired" signal.
	case msgTypeSignal:
		if _, err = d.Dec.ReadN(d.hdr.BodyLen); err != nil {
			return 0, fmt.Errorf("discard signal body: %w", err)
		}
		// Decode the following message.
		return d.DecodeMainPID(conn)
	}

	// Discard known signature "u".
	if _, err = d.Dec.Signature(); err != nil {
		return 0, fmt.Errorf("discard signature u: %w", err)
	}

	var pid uint32
	if pid, err = d.Dec.Uint32(); err != nil {
		return 0, fmt.Errorf("decode pid: %w", err)
	}

	return pid, nil
}

func newMessageEncoder() *messageEncoder {
	return &messageEncoder{
		Enc:  newEncoder(nil),
		Conv: newStringConverter(DefaultStringConverterSize),
	}
}

// messageEncoder is responsible for encoding and sending messages to dbus.
type messageEncoder struct {
	Enc  *encoder
	Conv *stringConverter

	// buf is a buffer where an encoder writes the message.
	buf bytes.Buffer
}

// EncodeHello encodes a hello request.
func (e *messageEncoder) EncodeHello(conn io.Writer, msgSerial uint32) error {
	// Reset the encoder to encode the header.
	e.buf.Reset()
	e.Enc.Reset(&e.buf)

	h := header{
		ByteOrder: littleEndian,
		Type:      msgTypeMethodCall,
		Proto:     1,
		Serial:    msgSerial,
		Fields: []headerField{
			{Signature: "s", S: "org.freedesktop.DBus", Code: fieldDestination},
			{Signature: "s", S: "Hello", Code: fieldMember},
			{Signature: "s", S: "org.freedesktop.DBus", Code: fieldInterface},
			{Signature: "o", S: "/org/freedesktop/DBus", Code: fieldPath},
		},
	}
	err := encodeHeader(e.Enc, &h)
	if err != nil {
		return fmt.Errorf("message header: %w", err)
	}

	if _, err = conn.Write(e.buf.Bytes()); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}

// EncodeListUnits encodes a request to systemd ListUnits method.
func (e *messageEncoder) EncodeListUnits(conn io.Writer, msgSerial uint32) error {
	// Reset the encoder to encode the header.
	e.buf.Reset()
	e.Enc.Reset(&e.buf)

	h := header{
		ByteOrder: littleEndian,
		Type:      msgTypeMethodCall,
		Proto:     1,
		Serial:    msgSerial,
		Fields: []headerField{
			{Signature: "s", S: "ListUnits", Code: fieldMember},
			{Signature: "s", S: "org.freedesktop.systemd1.Manager", Code: fieldInterface},
			{Signature: "o", S: "/org/freedesktop/systemd1", Code: fieldPath},
			{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
		},
	}
	err := encodeHeader(e.Enc, &h)
	if err != nil {
		return fmt.Errorf("message header: %w", err)
	}

	if _, err = conn.Write(e.buf.Bytes()); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}

// EncodeMainPID encodes MainPID property request for the given unit name,
// e.g., "dbus.service".
func (e *messageEncoder) EncodeMainPID(conn io.Writer, unitName string, msgSerial uint32) error {
	// Escape an object path to send a call to,
	// e.g., /org/freedesktop/systemd1/unit/dbus_2eservice.
	e.buf.Reset()
	e.buf.WriteString("/org/freedesktop/systemd1/unit/")
	escapeBusLabel(unitName, &e.buf)
	objPath := e.Conv.String(e.buf.Bytes())

	// Reset the encoder to encode the header and the body.
	e.buf.Reset()
	e.Enc.Reset(&e.buf)

	h := header{
		ByteOrder: littleEndian,
		Type:      msgTypeMethodCall,
		Proto:     1,
		Serial:    msgSerial,
		Fields: []headerField{
			{Signature: "o", S: objPath, Code: fieldPath},
			{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
			{Signature: "s", S: "Get", Code: fieldMember},
			{Signature: "s", S: "org.freedesktop.DBus.Properties", Code: fieldInterface},
			{Signature: "g", S: "ss", Code: fieldSignature},
		},
	}
	err := encodeHeader(e.Enc, &h)
	if err != nil {
		return fmt.Errorf("message header: %w", err)
	}

	// Encode message body with a known signature "ss".
	const (
		iface    = "org.freedesktop.systemd1.Service"
		propName = "MainPID"
	)
	bodyOffset := e.Enc.Offset()
	e.Enc.String(iface)
	e.Enc.String(propName)

	// Overwrite the h.BodyLen with an actual length of the message body.
	const headerBodyLenOffset = 4
	bodyLen := e.Enc.Offset() - bodyOffset
	if err = e.Enc.Uint32At(bodyLen, headerBodyLenOffset); err != nil {
		return fmt.Errorf("encode header BodyLen: %w", err)
	}

	if _, err = conn.Write(e.buf.Bytes()); err != nil {
		return fmt.Errorf("write message: %w", err)
	}

	return nil
}
