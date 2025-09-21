package main

import (
	"net"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/core"
)

const (
	shadowsocksCipherName   = "chacha20-ietf-poly1305"
	shadowsocksBasePassword = "Ssasnas1cSasd19jasc01515a"
)

var (
	ssOnce      sync.Once
	ssCipher    core.StreamConnCipher
	ssCipherErr error
)

func getShadowsocksCipher() (core.StreamConnCipher, error) {
	ssOnce.Do(func() {
		cipher, err := core.PickCipher(shadowsocksCipherName, nil, shadowsocksBasePassword)
		if err != nil {
			ssCipherErr = err
			return
		}
		ssCipher = cipher
	})
	return ssCipher, ssCipherErr
}

func configureTCPConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetNoDelay(true)
	}
}

type secureListener struct {
	net.Listener
	cipher core.StreamConnCipher
}

func (l *secureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	configureTCPConn(conn)
	return l.cipher.StreamConn(conn), nil
}

func listenSecure(address string) (net.Listener, error) {
	cipher, err := getShadowsocksCipher()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	return &secureListener{Listener: listener, cipher: cipher}, nil
}

func dialSecure(address, _ string) (net.Conn, error) {
	cipher, err := getShadowsocksCipher()
	if err != nil {
		return nil, err
	}
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	configureTCPConn(conn)
	return cipher.StreamConn(conn), nil
}
