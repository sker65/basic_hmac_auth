package handler

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/SenseUnit/basic_hmac_auth/hmac"
	"github.com/SenseUnit/basic_hmac_auth/proto"
)

const (
	// Sufficient for anything what might come from 64KB basic auth header
	DefaultBufferSize = 150 * 1024
)

type BasicHMACAuthHandler struct {
	Secret     []byte
	BufferSize int
}

func (a *BasicHMACAuthHandler) Run(input io.Reader, output io.Writer) error {
	bufSize := a.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	rd := bufio.NewReaderSize(input, bufSize)
	scanner := proto.NewElasticLineScanner(rd, '\n')

	for scanner.Scan() {
		parts := bytes.SplitN(scanner.Bytes(), []byte{' '}, 4)
		if len(parts) < 3 {
			err := fmt.Errorf("bad request line sent to auth helper: %q", string(scanner.Bytes()))
			return err
		}
		channelID := parts[0]
		username := proto.RFC1738Unescape(parts[1])
		password := proto.RFC1738Unescape(parts[2])

		if hmac.VerifyHMACLoginAndPassword(a.Secret, username, password) {
			fmt.Fprintf(output, "%s OK\n", channelID)
		} else {
			fmt.Fprintf(output, "%s ERR\n", channelID)
		}
	}

	return scanner.Err()
}
