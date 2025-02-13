package handler

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

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
	Strict     bool
}

func (a *BasicHMACAuthHandler) Run(input io.Reader, output io.Writer) error {
	bufSize := a.BufferSize
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	rd := bufio.NewReaderSize(input, bufSize)
	scanner := proto.NewElasticLineScanner(rd, '\n')

	verifier := hmac.NewVerifier(a.Secret, a.Strict)

	emitter := proto.NewResponseEmitter(output)
  proxy_pass := os.Getenv("PROXY_PASS")

	for scanner.Scan() {
		line := scanner.Bytes()

		before, after, found := bytes.Cut(line, []byte{' '})
		if !found {
			return fmt.Errorf("bad request line sent to auth helper: %q", line)
		}
		channelID := before

		before, after, found = bytes.Cut(after, []byte{' '})
		if !found {
			return fmt.Errorf("bad request line sent to auth helper: %q", line)
		}
		username := proto.RFC1738Unescape(before)

		before, _, _ = bytes.Cut(after, []byte{' '})
		password := proto.RFC1738Unescape(before)

		// just for the transitioning time: make the old static password also work
		if bytes.Equal(username, []byte("octo") ) && bytes.Equal( password, []byte(proxy_pass)) {
			if err := emitter.EmitOK(channelID); err != nil {
				return fmt.Errorf("response write failed: %w", err)
			}
			continue
		}

		if verifier.VerifyLoginAndPassword(username, password) {
			if err := emitter.EmitOK(channelID); err != nil {
				return fmt.Errorf("response write failed: %w", err)
			}
		} else {
			if err := emitter.EmitERR(channelID); err != nil {
				return fmt.Errorf("response write failed: %w", err)
			}
		}
	}

	return scanner.Err()
}
