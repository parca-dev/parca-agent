package systemd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
)

/*
authExternal performs EXTERNAL authentication,
see https://dbus.freedesktop.org/doc/dbus-specification.html#auth-protocol.
The protocol is a line-based, where each line ends with \r\n.

	client: AUTH EXTERNAL 31303030
	server: OK bde8d2222a9e966420ee8c1a63e972b4
	client: BEGIN

The client is authenticating as Unix uid 1000 in this example,
where 31303030 is ASCII decimal 1000 represented in hex.
*/
func authExternal(rw io.ReadWriter) error {
	var buf bytes.Buffer
	buf.WriteByte(0)
	// Send null byte as required by the protocol.
	_, err := rw.Write(buf.Bytes())
	if err != nil {
		return fmt.Errorf("send null failed: %w", err)
	}

	uid := strconv.Itoa(os.Geteuid())
	buf.Reset()
	buf.WriteString("AUTH EXTERNAL ")
	buf.WriteString(hex.EncodeToString([]byte(uid)))
	buf.WriteString("\r\n")
	if _, err = rw.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("AUTH EXTERNAL uid: %w", err)
	}

	// Read 37 bytes such as
	// "OK bde8d2222a9e966420ee8c1a63e972b4\r\n".
	buf.Reset()
	buf.Grow(37)
	b := buf.Bytes()[:buf.Cap()]
	if _, err = rw.Read(b); err != nil {
		return err
	}

	buf.Reset()
	buf.WriteString("OK")
	if !bytes.HasPrefix(b, []byte("OK")) {
		return fmt.Errorf("expected OK, got %s", b)
	}

	buf.Reset()
	buf.WriteString("BEGIN\r\n")
	if _, err = rw.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("BEGIN: %w", err)
	}

	return nil
}
