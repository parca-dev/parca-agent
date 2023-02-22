## Flexible bytes buffer

[![Go Report Card](https://goreportcard.com/badge/github.com/rzajac/flexbuf)](https://goreportcard.com/report/github.com/rzajac/flexbuf)
[![GoDoc](https://img.shields.io/badge/api-Godoc-blue.svg)](https://pkg.go.dev/github.com/rzajac/flexbuf)

Package `flexbuf` provides bytes buffer implementing many data access and 
manipulation interfaces.

    io.Writer
    io.WriterAt
    io.ByteWriter
    io.WriterTo
    io.StringWriter
    io.Reader
    io.ByteReader
    io.ReaderAt
    io.ReaderFrom
    io.Seeker
    io.Closer
    fmt.Stringer

Additionally, `flexbuf` provides `Truncate(size int64) error` method to make 
it almost a drop in replacement for `os.File`.

## Installation

```
go get github.com/rzajac/flexbuf
```

## Examples

```
buf := &flexbuf.Buffer{}

_, _ = buf.Write([]byte{0, 1, 2, 3})
_, _ = buf.Seek(-2, io.SeekEnd)
_, _ = buf.Write([]byte{4, 5})
_, _ = buf.Seek(0, io.SeekStart)

data, _ := ioutil.ReadAll(buf)
fmt.Println(data)

// Output: [0 1 4 5]
```

## How is it different from `bytes.Buffer`?

The `bytes.Buffer` always reads from current offset and writes to the end of 
the buffer, `flexbuf` behaves more like a file it reads and writes at current 
offset. Also `bytes.Buffer` doesn't implement interfaces:

- `io.WriterAt`
- `io.ReaderAt`
- `io.Seeker`
- `io.Closer`

or methods:

- `Truncate`

## Can I use `flexbuf.Buffer` as a replacement for `os.File`?

It depends. Even though `flexbuf.Buffer` probably implements all the methods 
you need to use it as a replacement for `os.File` there are some minor 
differences:

- `Truncate` method does not return `os.PathError` instances.
- `WriteAt` will not return error when used on an instance created with
    `flexbuf.New(flexbuf.Append)` or `flexbuf.With(myBuf, flexbuf.Append)`.

## Benchmarks

Some benchmarks between `flexbuf.Buffer` and `bytes.Buffer`:

```
BenchmarkWrite/flexbuf-12          124060         11014 ns/op       32768 B/op           1 allocs/op
BenchmarkWrite/bytes-12            101112         11767 ns/op       32768 B/op           1 allocs/op
BenchmarkWriteByte/flexbuf-12    38088462          31.2 ns/op           1 B/op           1 allocs/op
BenchmarkWriteByte/bytes-12      15355932          76.9 ns/op          64 B/op           1 allocs/op
BenchmarkWriteString/flexbuf-12  18013146          63.8 ns/op          16 B/op           1 allocs/op
BenchmarkWriteString/bytes-12    12852244          88.3 ns/op          64 B/op           1 allocs/op
BenchmarkReadFrom/flexbuf-12        27813         43573 ns/op      129024 B/op           7 allocs/op
BenchmarkReadFrom/bytes-12          27439         43440 ns/op      129024 B/op           7 allocs/op
```

## License

BSD-2-Clause