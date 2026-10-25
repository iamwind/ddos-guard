// mockssh 测试用 SSH 服务器：接受任意密码，记录收到的命令行到 stdout。
// 用法: go run mockssh.go -addr 127.0.0.1:2222
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "listen address")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		panic(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[mockssh] listening on %s\n", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handle(conn, cfg)
	}
}

func handle(c net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range requests {
				switch req.Type {
				case "pty-req":
					req.Reply(true, nil)
				case "shell":
					req.Reply(true, nil)
					go func() {
						buf := make([]byte, 1024)
						var line []byte
						for {
							n, err := ch.Read(buf)
							if n > 0 {
								line = append(line, buf[:n]...)
								for {
									idx := strings.IndexByte(string(line), '\n')
									if idx < 0 {
										break
									}
									cmd := strings.TrimSpace(string(line[:idx]))
									if cmd != "" {
										fmt.Printf("[mockssh] CMD: %s\n", cmd)
									}
									line = line[idx+1:]
									if cmd == "exit" {
										ch.Close()
										return
									}
								}
							}
							if err != nil {
								return
							}
						}
					}()
				default:
					req.Reply(false, nil)
				}
			}
		}()
	}
}
