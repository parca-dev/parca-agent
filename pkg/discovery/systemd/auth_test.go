package systemd

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAuthExternal(t *testing.T) {
	const authResp = "OK eb50e12940d90495b897de9f64090a3e\r\n"
	got := bytes.Buffer{}
	w := bufio.NewWriter(&got)
	rw := bufio.NewReadWriter(
		bufio.NewReader(bytes.NewBufferString(authResp)),
		w,
	)

	if err := authExternal(rw); err != nil {
		t.Fatal(err)
	}
	w.Flush()

	var want bytes.Buffer
	{
		uid := strconv.Itoa(os.Geteuid())
		want.WriteByte(0)
		want.WriteString("AUTH EXTERNAL ")
		want.WriteString(hex.EncodeToString([]byte(uid)))
		want.WriteString("\r\n")
		want.WriteString("BEGIN\r\n")
	}

	if diff := cmp.Diff(want.String(), got.String()); diff != "" {
		t.Fatal(diff)
	}
}

func BenchmarkAuthExternal(b *testing.B) {
	authResp := bytes.NewReader([]byte("OK eb50e12940d90495b897de9f64090a3e\r\n"))
	r := bufio.NewReader(authResp)
	got := bytes.Buffer{}
	w := bufio.NewWriter(&got)
	rw := bufio.NewReadWriter(r, w)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		authResp.Seek(0, io.SeekStart)
		got.Reset()

		if err := authExternal(rw); err != nil {
			b.Fatal(err)
		}
	}
}
