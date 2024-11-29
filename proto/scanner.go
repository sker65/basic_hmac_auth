package proto

import "io"

type BytesReader interface {
	ReadBytes(byte) ([]byte, error)
}

type ElasticLineScanner struct {
	line    []byte
	reader  BytesReader
	lastErr error
	done    bool
	delim   byte
}

func NewElasticLineScanner(reader BytesReader, delim byte) *ElasticLineScanner {
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

	data, err := els.reader.ReadBytes(els.delim)
	if err != nil {
		els.done = true
		els.lastErr = err
		if len(data) == 0 {
			return false
		}
	} else {
		// strip delimiter if needed
		if len(data) > 0 && data[len(data)-1] == els.delim {
			data = data[:len(data)-1]
		}
	}
	els.line = data
	return true
}
