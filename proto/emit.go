package proto

import (
	"bytes"
	"io"
)

const (
	OK  = "OK"
	ERR = "ERR"
)

type ResponseEmitter struct {
	writer io.Writer
	buffer bytes.Buffer
}

func NewResponseEmitter(writer io.Writer) *ResponseEmitter {
	return &ResponseEmitter{
		writer: writer,
	}
}

func (e *ResponseEmitter) EmitOK(channelID []byte) error {
	e.beginResponse(channelID)
	e.buffer.WriteString(OK)
	return e.finishResponse()
}

func (e *ResponseEmitter) EmitERR(channelID []byte) error {
	e.beginResponse(channelID)
	e.buffer.WriteString(ERR)
	return e.finishResponse()
}

func (e *ResponseEmitter) beginResponse(channelID []byte) {
	e.buffer.Reset()
	e.buffer.Write(channelID)
	e.buffer.WriteByte(' ')
}

func (e *ResponseEmitter) finishResponse() error {
	e.buffer.WriteByte('\n')
	_, err := e.buffer.WriteTo(e.writer)
	return err
}
