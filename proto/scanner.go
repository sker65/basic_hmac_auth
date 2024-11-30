package proto

import (
	"bufio"
	"io"
)

type ReadSlicer interface {
	ReadSlice(byte) ([]byte, error)
}

type ElasticLineScanner struct {
	line    []byte
	reader  ReadSlicer
	lastErr error
	done    bool
	delim   byte
}

func NewElasticLineScanner(reader ReadSlicer, delim byte) *ElasticLineScanner {
	return &ElasticLineScanner{
		reader: reader,
		delim:  delim,
	}
}

func (els *ElasticLineScanner) Err() error {
	if els.lastErr == io.EOF {
		return nil
	}
	return els.lastErr
}

func (els *ElasticLineScanner) Bytes() []byte {
	return els.line
}

func (els *ElasticLineScanner) Scan() bool {
	if els.done {
		return false
	}

	els.line = els.line[:0]
	var (
		data []byte
		err  error
	)
	for data, err = els.reader.ReadSlice(els.delim); ; data, err = els.reader.ReadSlice(els.delim) {
		els.line = append(els.line, data...)
		if err != bufio.ErrBufferFull {
			break
		}
	}
	if err != nil {
		els.done = true
		els.lastErr = err
		if len(els.line) == 0 {
			return false
		}
	} else {
		// strip delimiter if needed
		if len(els.line) > 0 && els.line[len(els.line)-1] == els.delim {
			els.line = els.line[:len(els.line)-1]
		}
	}
	return true
}
