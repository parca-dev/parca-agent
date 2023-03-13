// Package flexbuf provides bytes buffer implementing many data access and
// manipulation interfaces.
//
//     io.Writer
//     io.WriterAt
//     io.ByteWriter
//     io.WriterTo
//     io.StringWriter
//     io.Reader
//     io.ByteReader
//     io.ReaderAt
//     io.ReaderFrom
//     io.Seeker
//     io.Closer
//     fmt.Stringer
//
// Additionally, `flexbuf` provides `Truncate(size int64) error` method to make
// it almost a drop in replacement for `os.File`.
//

package flexbuf

import (
	"bytes"
	"errors"
	"io"
	"os"
)

// smallBufferSize is an initial allocation minimal capacity.
const smallBufferSize = 64

// ErrOutOfBounds is returned for invalid offsets.
var ErrOutOfBounds = errors.New("offset out of bounds")

// Offset is the constructor option setting the initial buffer offset to off.
func Offset(off int) func(*Buffer) {
	return func(b *Buffer) {
		b.off = off
	}
}

// Append is the constructor option setting the initial offset
// to the end of the buffer. Also when Truncate is used the offset will
// be set to the end of the buffer.
// Append should be the last option on the option list.
func Append(buf *Buffer) {
	buf.flag |= os.O_APPEND
	buf.off = len(buf.buf)
}

// A Buffer is a variable-sized buffer of bytes.
// The zero value for Buffer is an empty buffer ready to use.
type Buffer struct {
	// Flags passed when creating the Buffer.
	// Flags are used to match behaviour of the Buffer to os.File.
	flag int
	// Current offset for read and write operations.
	off int
	// Underlying buffer.
	buf []byte
}

// New returns new instance of the Buffer. The difference between New and
// using zero value buffer is that New will initialize buffer with capacity
// of bytes.MinRead. It will panic with ErrOutOfBounds if option sets offset
// as negative number or greater then bytes.MinRead.
func New(opts ...func(buffer *Buffer)) *Buffer {
	return With(make([]byte, 0, bytes.MinRead), opts...)
}

// With creates new instance of Buffer initialized with data. The new Buffer
// takes ownership of buf, and the caller should not use buf after this call.
// NewBuffer is intended to prepare a Buffer to read existing data. It can
// also be used to set the initial size of the internal buffer for writing.
// To do that, buf should have the desired capacity but a length of zero.
// It will panic with ErrOutOfBounds if option sets offset as negative number
// or beyond buffer length.
func With(data []byte, opts ...func(*Buffer)) *Buffer {
	b := &Buffer{
		buf: data,
	}

	for _, opt := range opts {
		opt(b)
	}

	if b.off < 0 || b.off > len(b.buf) {
		panic(ErrOutOfBounds)
	}

	return b
}

// Release releases ownership of the underlying buffer, the caller should not
// use the instance of Buffer after this call.
func (b *Buffer) Release() []byte {
	buf := b.buf
	b.off = 0
	b.buf = nil
	return buf
}

// Write writes the contents of p to the buffer at current offset, growing
// the buffer as needed. The return value n is the length of p; err is
// always nil.
func (b *Buffer) Write(p []byte) (int, error) {
	return b.write(p), nil
}

// WriteByte writes single byte c to the buffer.
func (b *Buffer) WriteByte(c byte) error {
	b.write([]byte{c})
	return nil
}

// WriteAt writes len(p) bytes to the buffer starting at byte offset off.
// It returns the number of bytes written; err is always nil. It does not
// change the offset.
func (b *Buffer) WriteAt(p []byte, off int64) (int, error) {
	prev := b.off
	c := cap(b.buf)
	pl := len(p)

	// Handle write beyond capacity.
	if int(off)+pl > c {
		b.off = c // So tryGrowByReslice returns false.
		b.grow(int(off) + pl - len(b.buf))
		b.buf = b.buf[:int(off)+pl]
	}

	b.off = int(off)
	n := b.write(p)
	b.off = prev
	return n, nil
}

// WriteTo writes data to w starting at current offset until there's no
// more data to write or when an error occurs. The return value n is the
// number of bytes written. Any error encountered during the write is
// also returned.
func (b *Buffer) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(b.buf[b.off:])
	b.off += n
	return int64(n), err
}

// WriteString writes string s to the buffer at current offset.
func (b *Buffer) WriteString(s string) (int, error) {
	return b.Write([]byte(s))
}

// write writes p at offset b.off.
func (b *Buffer) write(p []byte) int {
	l := len(b.buf)
	b.grow(len(p))
	n := copy(b.buf[b.off:], p)
	b.off += n
	if b.off > l {
		l = b.off
	}
	b.buf = b.buf[:l]
	return n
}

// Read reads the next len(p) bytes from the buffer or until the buffer
// is drained. The return value is the number of bytes read. If the
// buffer has no data to return, err is io.EOF (unless len(p) is zero);
// otherwise it is nil.
func (b *Buffer) Read(p []byte) (int, error) {
	// Nothing more to read.
	if len(p) > 0 && b.off >= len(b.buf) {
		return 0, io.EOF
	}
	n := copy(p, b.buf[b.off:])
	b.off += n
	return n, nil
}

// ReadByte reads and returns the next byte from the buffer or
// any error encountered. If ReadByte returns an error, no input
// byte was consumed, and the returned byte value is undefined.
func (b *Buffer) ReadByte() (byte, error) {
	// Nothing more to read.
	if b.off >= len(b.buf) {
		return 0, io.EOF
	}
	v := b.buf[b.off]
	b.off++
	return v, nil
}

// ReadAt reads len(p) bytes from the buffer starting at byte offset off.
// It returns the number of bytes read and the error, if any.
// ReadAt always returns a non-nil error when n < len(p). It does not
// change the offset.
func (b *Buffer) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b.buf)) {
		return 0, io.EOF
	}
	prev := b.off
	defer func() { b.off = prev }()
	b.off = int(off)
	n, err := b.Read(p)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReadFrom reads data from r until EOF and appends it to the buffer at b.off,
// growing the buffer as needed. The return value is the number of bytes read.
// Any error except io.EOF encountered during the read is also returned. If the
// buffer becomes too large, ReadFrom will panic with ErrTooLarge.
func (b *Buffer) ReadFrom(r io.Reader) (int64, error) {
	var err error
	var n, total int

	for {

		// Length before growing the buffer.
		l := len(b.buf)

		// Make sure we can fit MinRead between b.off and new buffer length.
		b.grow(bytes.MinRead)

		// We will use bytes between l and cap(b.buf) as a temporary
		// scratch space for reading from r and then slide read bytes
		// to place. We have to do it this way because io.Read documentation
		// says that: "Even if Read returns n < len(p), it may use all of p
		// as scratch space during the call." so we can't pass our buffer
		// to Read because it might change parts of it not involved in
		// read operation.
		tmp := b.buf[l:cap(b.buf)]
		n, err = r.Read(tmp)

		if l != b.off {
			// Move bytes from temporary area to correct place.
			copy(b.buf[b.off:], tmp[:n])
			if n < len(tmp) {
				// Clean up any garbage reader might put in there and
				// we want to keep all bytes between len and cap as zeros.
				zeroOutSlice(tmp[n:])
			}
		}

		b.off += n
		total += n

		if b.off > l {
			l = b.off
		}

		// Set proper buffer length.
		b.buf = b.buf[:l]

		if err != nil {
			break
		}
	}

	// The io.EOF is not an error.
	if err == io.EOF {
		return int64(total), nil
	}

	return int64(total), err
}

// String returns string representation of the buffer starting at current
// offset. Calling this method is considered as reading the buffer and
// advances offset to the end of the buffer.
func (b *Buffer) String() string {
	s := string(b.buf[b.off:])
	b.off = len(b.buf)
	return s
}

// Seek sets the offset for the next Read or Write on the buffer to offset,
// interpreted according to whence: 0 means relative to the origin of the file,
// 1 means relative to the current offset, and 2 means relative to the end.
// It returns the new offset and an error (only if calculated offset < 0).
func (b *Buffer) Seek(offset int64, whence int) (int64, error) {
	var off int
	switch whence {
	case io.SeekStart:
		off = int(offset)
	case io.SeekCurrent:
		off = b.off + int(offset)
	case io.SeekEnd:
		off = len(b.buf) + int(offset)
	}

	if off < 0 {
		return 0, os.ErrInvalid
	}
	b.off = off

	return int64(b.off), nil
}

// SeekStart is a convenience method setting the buffer's offset to zero
// and returning the value it had before the method was called.
func (b *Buffer) SeekStart() int64 {
	prev := b.off
	b.off = 0
	return int64(prev)
}

// SeekEnd is a convenience method setting the buffer's offset to the buffer
// length and returning the value it had before the method was called.
func (b *Buffer) SeekEnd() int64 {
	prev := b.off
	b.off = len(b.buf)
	return int64(prev)
}

// Truncate changes the size of the buffer discarding bytes at offsets greater
// then size. It does not change the offset unless Append option was used then
// it sets offset to the end of the buffer. It returns error os.ErrInvalid
// only when when size is negative.
func (b *Buffer) Truncate(size int64) error {
	if size < 0 {
		return os.ErrInvalid
	}

	prev := b.off
	l := len(b.buf)
	c := cap(b.buf)

	switch {
	case int(size) == l:
		// Nothing to do.

	case int(size) == c:
		// Reslice.
		b.buf = b.buf[:size]

	case int(size) > l && int(size) < c:
		// Truncate between len and cap.
		b.buf = b.buf[:size]

	case int(size) > c:
		// Truncate beyond cap.
		b.off = c // So tryGrowByReslice returns false.
		b.grow(int(size) - l)
		b.buf = b.buf[:int(size)]

	default:
		// Reduce the size of the buffer.
		zeroOutSlice(b.buf[size:])
		b.buf = b.buf[:size]
	}

	b.off = prev
	if b.flag&os.O_APPEND != 0 {
		b.off = int(size)
	}

	return nil
}

// Grow grows the buffer's capacity, if necessary, to guarantee space for
// another n bytes. After Grow(n), at least n bytes can be written to the
// buffer without another allocation.
// If n is negative, Grow will panic.
// If the buffer can't grow it will panic with ErrTooLarge.
func (b *Buffer) Grow(n int) {
	if n < 0 {
		panic("flexbuf.Buffer.Grow: negative count")
	}

	l := len(b.buf)
	if l+n <= cap(b.buf) {
		return
	}

	// Allocate bigger buffer.
	tmp := makeSlice(l + n)
	copy(tmp, b.buf)
	b.buf = tmp
	b.buf = b.buf[:l]
}

// grow grows the buffer capacity to guarantee space for n more bytes. In
// another words it makes sure there is n bytes between b.off and buffer
// capacity. It's worth noting that after calling this method the len(b.buf)
// changes. If the buffer can't grow it will panic with ErrTooLarge.
func (b *Buffer) grow(n int) {
	// Try to grow by means of a reslice.
	if ok := b.tryGrowByReslice(n); ok {
		return
	}
	if b.buf == nil && n <= smallBufferSize {
		b.buf = make([]byte, n, smallBufferSize)
		return
	}
	// Allocate bigger buffer.
	tmp := makeSlice(cap(b.buf)*2 + n) // cap(b.buf) may be zero.
	copy(tmp, b.buf)
	b.buf = tmp
}

// tryGrowByReslice is a inlineable version of grow for the fast-case where the
// internal buffer only needs to be resliced. It returns whether it succeeded.
func (b *Buffer) tryGrowByReslice(n int) bool {
	// No need to do anything if there is enough space
	// between current offset and the length of the buffer.
	if n <= len(b.buf)-b.off {
		return true
	}

	if n <= cap(b.buf)-b.off {
		b.buf = b.buf[:b.off+n]
		return true
	}
	return false
}

// makeSlice allocates a slice of size n. If the allocation fails, it panics
// with ErrTooLarge.
func makeSlice(n int) []byte {
	// If the make fails, give a known error.
	defer func() {
		if recover() != nil {
			panic(bytes.ErrTooLarge)
		}
	}()
	return make([]byte, n)
}

// zeroOutSlice zeroes out the byte slice.
// TODO: Test cases where this is used.
func zeroOutSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Offset returns the current offset.
func (b *Buffer) Offset() int {
	return b.off
}

// Len returns the number of bytes in the buffer.
func (b *Buffer) Len() int {
	return len(b.buf)
}

// Cap returns the capacity of the buffer's underlying byte slice, that is,
// the total space allocated for the buffer's data.
func (b *Buffer) Cap() int {
	return cap(b.buf)
}

// Close sets offset to zero and zero put the buffer. It always returns
// nil error.
func (b *Buffer) Close() error {
	if b == nil {
		return nil
	}
	b.off = 0
	zeroOutSlice(b.buf[0:len(b.buf)])
	b.buf = b.buf[:0]
	return nil
}
