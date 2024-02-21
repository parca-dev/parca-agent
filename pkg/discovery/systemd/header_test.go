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
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeHeader(t *testing.T) {
	tt := map[string]struct {
		in   []byte
		want header
	}{
		"hello request": {
			in: helloRequest,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodCall,
				Flags:     0,
				Proto:     1,
				BodyLen:   0,
				Serial:    1,
				FieldsLen: 110,
				Fields: []headerField{
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldDestination},
					{Signature: "s", S: "Hello", Code: fieldMember},
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldInterface},
					{Signature: "o", S: "/org/freedesktop/DBus", Code: fieldPath},
				},
			},
		},
		"hello response": {
			in: helloResponse,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodReply,
				Flags:     1,
				Proto:     1,
				BodyLen:   10,
				Serial:    1,
				FieldsLen: 61,
				Fields: []headerField{
					{Signature: "s", S: ":1.47", Code: fieldDestination},
					{Signature: "u", U: 1, Code: fieldReplySerial},
					{Signature: "g", S: "s", Code: fieldSignature},
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldSender},
				},
			},
		},
		"name acquired signal": {
			in: nameAcquiredSignal,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeSignal,
				Flags:     1,
				Proto:     1,
				BodyLen:   11,
				Serial:    2,
				FieldsLen: 141,
				Fields: []headerField{
					{Signature: "o", S: "/org/freedesktop/DBus", Code: fieldPath},
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldInterface},
					{Signature: "s", S: "NameAcquired", Code: fieldMember},
					{Signature: "s", S: ":1.100", Code: fieldDestination},
					{Signature: "g", S: "s", Code: fieldSignature},
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldSender},
				},
			},
		},
		"pid request": {
			in: mainPIDRequest,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodCall,
				Flags:     0,
				Proto:     1,
				BodyLen:   52,
				Serial:    3,
				FieldsLen: 160,
				Fields: []headerField{
					{Signature: "o", S: "/org/freedesktop/systemd1/unit/dbus_2eservice", Code: fieldPath},
					{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
					{Signature: "s", S: "Get", Code: fieldMember},
					{Signature: "s", S: "org.freedesktop.DBus.Properties", Code: fieldInterface},
					{Signature: "g", S: "ss", Code: fieldSignature},
				},
			},
		},
		"pid response": {
			in: mainPIDResponse,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodReply,
				Flags:     1,
				Proto:     1,
				BodyLen:   8,
				Serial:    2263,
				FieldsLen: 45,
				Fields: []headerField{
					{Signature: "u", U: 3, Code: fieldReplySerial},
					{Signature: "s", S: ":1.388", Code: fieldDestination},
					{Signature: "g", S: "v", Code: fieldSignature},
					{Signature: "s", S: ":1.0", Code: fieldSender},
				},
			},
		},
		"pid unknown property response": {
			in: mainPIDUnknownPropertyResponse,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeError,
				Flags:     1,
				Proto:     1,
				BodyLen:   76,
				Serial:    4655,
				FieldsLen: 103,
				Fields: []headerField{
					{Signature: "u", U: 4, Code: fieldReplySerial},
					{Signature: "s", S: ":1.568", Code: fieldDestination},
					{Signature: "s", S: "org.freedesktop.DBus.Error.UnknownProperty", Code: fieldErrorName},
					{Signature: "g", S: "s", Code: fieldSignature},
					{Signature: "s", S: ":1.489", Code: fieldSender},
				},
			},
		},
		"units request": {
			in: listUnitsRequest,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodCall,
				Flags:     0,
				Proto:     1,
				BodyLen:   0,
				Serial:    2,
				FieldsLen: 145,
				Fields: []headerField{
					{Signature: "s", S: "ListUnits", Code: fieldMember},
					{Signature: "s", S: "org.freedesktop.systemd1.Manager", Code: fieldInterface},
					{Signature: "o", S: "/org/freedesktop/systemd1", Code: fieldPath},
					{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
				},
			},
		},
		"units response": {
			in: listUnitsResponse,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodReply,
				Flags:     1,
				Proto:     1,
				BodyLen:   35714,
				Serial:    1758,
				FieldsLen: 61,
				Fields: []headerField{
					{Signature: "u", U: 2, Code: fieldReplySerial},
					{Signature: "s", S: ":1.308", Code: fieldDestination},
					{Signature: "g", S: "a(ssssssouso)", Code: fieldSignature},
					{Signature: "s", S: ":1.0", Code: fieldSender},
				},
			},
		},
		"units access denied response": {
			in: listUnitsAccessDeniedResponse,
			want: header{
				ByteOrder: littleEndian,
				Type:      msgTypeError,
				Flags:     1,
				Proto:     1,
				BodyLen:   409,
				Serial:    3,
				FieldsLen: 109,
				Fields: []headerField{
					{Signature: "s", S: ":1.573", Code: fieldDestination},
					{Signature: "s", S: "org.freedesktop.DBus.Error.AccessDenied", Code: fieldErrorName},
					{Signature: "u", U: 1, Code: fieldReplySerial},
					{Signature: "g", S: "s", Code: fieldSignature},
					{Signature: "s", S: "org.freedesktop.DBus", Code: fieldSender},
				},
			},
		},
	}

	conv := newStringConverter(DefaultStringConverterSize)

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			dec := newDecoder(bytes.NewReader(tc.in))

			var h header
			if err := decodeHeader(dec, conv, &h, false); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.want, h); diff != "" {
				t.Errorf(diff)
			}
		})
	}
}

func FuzzDecodeHeader(f *testing.F) {
	conv := newStringConverter(DefaultStringConverterSize)

	tt := [][]byte{
		helloRequest,
		helloResponse,
		nameAcquiredSignal,
		mainPIDRequest,
		mainPIDResponse,
		mainPIDUnknownPropertyResponse,
		listUnitsRequest,
		listUnitsResponse,
		listUnitsAccessDeniedResponse,
	}
	for _, tc := range tt {
		f.Add(tc)
	}

	f.Fuzz(func(t *testing.T, orig []byte) {
		dec := newDecoder(bytes.NewReader(orig))
		// Mustn't panic.
		decodeHeader(dec, conv, &header{}, false)
	})
}

func BenchmarkDecodeHeader(b *testing.B) {
	conn := bytes.NewReader(mainPIDResponse)
	dec := newDecoder(conn)
	conv := newStringConverter(DefaultStringConverterSize)
	var h header

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.Seek(0, io.SeekStart)

		if err := decodeHeader(dec, conv, &h, false); err != nil {
			b.Error(err)
		}
	}
}

func TestEncodeHeader(t *testing.T) {
	tt := map[string]struct {
		want []byte
		h    header
	}{
		"pid request": {
			want: mainPIDRequest,
			h: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodCall,
				Flags:     0,
				Proto:     1,
				BodyLen:   52,
				Serial:    3,
				FieldsLen: 160,
				Fields: []headerField{
					{Signature: "o", S: "/org/freedesktop/systemd1/unit/dbus_2eservice", Code: fieldPath},
					{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
					{Signature: "s", S: "Get", Code: fieldMember},
					{Signature: "s", S: "org.freedesktop.DBus.Properties", Code: fieldInterface},
					{Signature: "g", S: "ss", Code: fieldSignature},
				},
			},
		},
		"pid response": {
			want: mainPIDResponse,
			h: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodReply,
				Flags:     1,
				Proto:     1,
				BodyLen:   8,
				Serial:    2263,
				FieldsLen: 45,
				Fields: []headerField{
					{Signature: "u", U: 3, Code: fieldReplySerial},
					{Signature: "s", S: ":1.388", Code: fieldDestination},
					{Signature: "g", S: "v", Code: fieldSignature},
					{Signature: "s", S: ":1.0", Code: fieldSender},
				},
			},
		},
		"units request": {
			want: listUnitsRequest,
			h: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodCall,
				Flags:     0,
				Proto:     1,
				BodyLen:   0,
				Serial:    2,
				FieldsLen: 145,
				Fields: []headerField{
					{Signature: "s", S: "ListUnits", Code: fieldMember},
					{Signature: "s", S: "org.freedesktop.systemd1.Manager", Code: fieldInterface},
					{Signature: "o", S: "/org/freedesktop/systemd1", Code: fieldPath},
					{Signature: "s", S: "org.freedesktop.systemd1", Code: fieldDestination},
				},
			},
		},
		"units response": {
			want: listUnitsResponse,
			h: header{
				ByteOrder: littleEndian,
				Type:      msgTypeMethodReply,
				Flags:     1,
				Proto:     1,
				BodyLen:   35714,
				Serial:    1758,
				FieldsLen: 61,
				Fields: []headerField{
					{Signature: "u", U: 2, Code: fieldReplySerial},
					{Signature: "s", S: ":1.308", Code: fieldDestination},
					{Signature: "g", S: "a(ssssssouso)", Code: fieldSignature},
					{Signature: "s", S: ":1.0", Code: fieldSender},
				},
			},
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			dst := bytes.Buffer{}
			enc := newEncoder(&dst)

			if err := encodeHeader(enc, &tc.h); err != nil {
				t.Fatal(err)
			}

			wantHdrLen := tc.h.Len()
			if int(wantHdrLen) != dst.Len() {
				t.Errorf("expected header len %d, got %d", wantHdrLen, dst.Len())
			}

			want := tc.want[:wantHdrLen]
			if diff := cmp.Diff(want, dst.Bytes()); diff != "" {
				t.Error(diff, want, dst.Bytes())
			}
		})
	}
}

func BenchmarkEncodeHeader(b *testing.B) {
	dst := &bytes.Buffer{}
	enc := newEncoder(dst)
	h := header{
		ByteOrder: littleEndian,
		Type:      msgTypeMethodReply,
		Flags:     1,
		Proto:     1,
		BodyLen:   8,
		Serial:    2263,
		FieldsLen: 45,
		Fields: []headerField{
			{Signature: "u", U: 3, Code: fieldReplySerial},
			{Signature: "s", S: ":1.388", Code: fieldDestination},
			{Signature: "g", S: "v", Code: fieldSignature},
			{Signature: "s", S: ":1.0", Code: fieldSender},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst.Reset()
		enc.Reset(dst)

		if err := encodeHeader(enc, &h); err != nil {
			b.Error(err)
		}
	}
}
