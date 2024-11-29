package handler

import (
	"bufio"
	"io"
	"log"

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
		log.Printf("line=%q", string(scanner.Bytes()))
	}

	return scanner.Err()
}
