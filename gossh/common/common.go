package common

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"net"
)

const debugCommon = false

const MsgExecutionRequest = 1
const MsgExecutionResponse = 2
const MsgHandoffComplete = 10

const MsgExecutionDenied = 0
const MsgExecutionApproved = 1

type ExecutionApprovedMessage struct {
	MsgNum byte
}

type ExecutionResponseMessage struct {
	MsgNum byte
	Response byte
	Reason string
}

type ExecutionRequestMessage struct {
	MsgNum  byte
	User    string
	Command string
	Server  string
}

type HandoffCompleteMessage struct {
	MsgNum            byte
	NextTransportByte uint32
}

type CustomConn struct {
	net.Conn
	RemoteAddress net.Addr
	bytesRead     int
	bytesWritten  int
}

func (cc *CustomConn) RemoteAddr() net.Addr {
	if cc.RemoteAddress != nil {
		return cc.RemoteAddress
	}
	return cc.Conn.RemoteAddr()
}

func (cc *CustomConn) BytesRead() int {
	return cc.bytesRead
}

func (cc *CustomConn) BytesWritten() int {
	return cc.bytesWritten
}

func (cc *CustomConn) Read(p []byte) (n int, err error) {
	n, err = cc.Conn.Read(p)
	cc.bytesRead += n
	return
}

func (cc *CustomConn) Write(b []byte) (n int, err error) {
	n, err = cc.Conn.Write(b)
	cc.bytesWritten += n
	return
}

func ReadControlPacket(r io.Reader) (p []byte, err error) {
	var packetLenBytes [4]byte
	_, err = io.ReadFull(r, packetLenBytes[:])
	if err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(packetLenBytes[:])
	if debugCommon {
		log.Printf("read len bytes: %s, len: %d", hex.EncodeToString(packetLenBytes[:]), length)
	}
	p = make([]byte, length)
	_, err = io.ReadFull(r, p[:])
	if debugCommon {
		log.Printf("read: %s", hex.EncodeToString(p[:]))
	}

	return p, err
}

func WriteControlPacket(w io.Writer, p []byte) error {
	var packetLenBytes [4]byte
	binary.BigEndian.PutUint32(packetLenBytes[:], uint32(len(p)))
	if debugCommon {
		log.Printf("written len: %s", hex.EncodeToString(packetLenBytes[:]))
	}
	if _, err := w.Write(packetLenBytes[:]); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}
