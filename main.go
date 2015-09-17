package main

import (
	"bufio"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/fsouza/go-dockerclient"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
	"wrongssh/readED"
	"wrongssh/ssh" // import "golang.org/x/crypto/ssh"
)

// #cgo LDFLAGS: -lcrypt
// #define _GNU_SOURCE
// #include <crypt.h>
// #include <stdlib.h>
import "C"

// crypt wraps C library crypt_r
func crypt(key, salt string) string {
	data := C.struct_crypt_data{}
	ckey := C.CString(key)
	csalt := C.CString(salt)
	out := C.GoString(C.crypt_r(ckey, csalt, &data))
	C.free(unsafe.Pointer(ckey))
	C.free(unsafe.Pointer(csalt))
	return out
}

var rcli *docker.Client

var (
	ErrAccessDenied = errors.New("Access denied")
	ErrNoContainer  = errors.New("No such container")
	ErrNoPasswd     = errors.New("No password database found")
)

func mapUser(login string) (container *docker.Container, user string) {
	idx := strings.LastIndex(login, "@")
	last_part := login[idx+1:]
	first_part := "root"
	if idx != -1 {
		first_part = login[0:idx]
	}

	container, err := rcli.InspectContainer(last_part)

	if err != nil {
		switch err.(type) {
		case *docker.NoSuchContainer:
			return nil, first_part
		default:
			log.Fatal(err)
		}
	}

	return container, first_part
}

func main() {
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			container, user := mapUser(c.User())
			if container == nil {
				log.Printf("No container found for %s.\n", c.User())
				return nil, ErrNoContainer
			}

			fname := fmt.Sprintf("/proc/%d/root/etc/shadow", container.State.Pid)
			file, err := os.Open(fname)
			if err != nil {
				log.Printf("No shadow password database for container %s has been found.\n",
					container.ID)
				return nil, ErrNoPasswd
			}
			defer file.Close()

			for scanner := bufio.NewScanner(file); scanner.Scan(); {
				parts := strings.SplitN(scanner.Text(), ":", 3)
				if parts[0] == user {
					if hmac.Equal([]byte(crypt(string(pass), parts[1])), []byte(parts[1])) {
						return &ssh.Permissions{Extensions: map[string]string{
							"container_id": container.ID,
							"pid":          fmt.Sprintf("%d", container.State.Pid),
							"user":         user,
						}}, nil
					} else {
						log.Printf("Bad password for user %s in container %s.\n",
							parts[0], container.ID)
					}
				}
			}

			return nil, ErrAccessDenied
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			container, user := mapUser(c.User())
			if container == nil {
				log.Printf("No container found for %s.\n", c.User())
				return nil, ErrNoContainer
			}
			fname := fmt.Sprintf("/proc/%d/root/etc/passwd", container.State.Pid)
			file, err := os.Open(fname)
			if err != nil {
				log.Printf("No password database for container %s has been found.\n",
					container.ID)
				return nil, ErrNoPasswd
			}
			defer file.Close()

			for scanner := bufio.NewScanner(file); scanner.Scan(); {
				parts := strings.SplitN(scanner.Text(), ":", 7)
				if len(parts) == 7 && parts[0] == user {
					fname := fmt.Sprintf("/proc/%d/root/%s/.ssh/authorized_keys",
						container.State.Pid, parts[5])
					log.Printf("Trying %s...\n", fname)
					akeys, err := ioutil.ReadFile(fname)
					if err == nil {
						for {
							if len(akeys) == 0 {
								break
							}
							var pk ssh.PublicKey
							pk, _, _, akeys, err = ssh.ParseAuthorizedKey(akeys)
							if err != nil {
								break
							}
							if hmac.Equal(pk.Marshal(), key.Marshal()) {
								return &ssh.Permissions{Extensions: map[string]string{
									"container_id": container.ID,
									"pid":          fmt.Sprintf("%d", container.State.Pid),
									"user":         user,
								}}, nil
							}
						}
					}
				}
			}

			return nil, ErrAccessDenied
		},
		ServerVersion: "SSH-2.0-wrongssh github.com/kmeaw/wrongssh",
	}

	var err error
	rcli, err = docker.NewClient("tcp://localhost:2375")
	if err != nil {
		log.Fatal(err)
	}

	config.Config = ssh.Config{
		KeyExchanges: []string{
			"curve25519-sha256@libssh.org",
			"diffie-hellman-group-exchange-sha256",
		},
		Ciphers: []string{
			"chacha20-poly1305@openssh.com",
			"aes256-gcm@openssh.com",
			"aes128-gcm@openssh.com",
			"aes256-ctr",
			"aes192-ctr",
			"aes128-ctr",
		},
		MACs: []string{"hmac-sha2-256"},
		//	MACs: []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-512", "hmac-sha2-256", "hmac-ripemd160", "umac-128@openssh.com"},
	}
	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	privateBytes, err = ioutil.ReadFile("id_ed25519")
	if err != nil {
		log.Fatal("Failed to load private key (./id_ed25519)")
	}

	private, err = readED.ParseEDPrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		defer func() {
			if r := recover(); r != nil {
				tcpConn.Close()
				log.Printf("Connection aborted, got panic: %v.\n", r)
			}
		}()
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)",
			sshConn.RemoteAddr(),
			sshConn.ClientVersion())
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans, sshConn)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, sshConn *ssh.ServerConn) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel, sshConn)
	}
}

func handleChannel(newChannel ssh.NewChannel, sshConn *ssh.ServerConn) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType,
			fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	fail := func(err error) {
		if err != nil {
			connection.Write([]byte("Oops: "))
			logger := log.New(connection, "Oops: ", log.Lshortfile)
			logger.Print(err)
		}
		log.Println("Closing the connection...")
		connection.Close()
	}

	if sshConn.Permissions == nil {
		err = ErrAccessDenied
	}

	if err != nil {
		fail(err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		var execReq *docker.Exec
		var sftp *exec.Cmd

		w, h := 0, 0

		cmd := []string{"/usr/bin/env", "bash", "--login"}
		tty := false
		for req := range requests {
			log.Printf("Got req %s.\n", req.Type)
			switch req.Type {
			case "env":
				namelen := binary.BigEndian.Uint32(req.Payload)
				name := string(req.Payload[4 : namelen+4])
				vallen := binary.BigEndian.Uint32(req.Payload[namelen+4:])
				value := string(req.Payload[4+namelen+4 : 4+namelen+4+vallen])
				cmd = append([]string{"/usr/bin/env", name + "=" + value}, cmd[1:]...)
			case "subsystem":
				len := binary.BigEndian.Uint32(req.Payload)
				pl := string(req.Payload[4 : len+4])
				switch pl {
				case "sftp":
					sftp = exec.Command(
						"env",
						"LD_PRELOAD=/root/libchroot.so",
						fmt.Sprintf("CHROOT=/proc/%s/root", sshConn.Permissions.Extensions["pid"]),
						"/usr/lib64/misc/sftp-server",
					)
					sftp.Stdin = connection
					sftp.Stdout = connection
					sftp.Stderr = connection.Stderr()
					connection.Stderr().Write([]byte("\033[0mgithub.com/kmeaw/wrongssh  *  a \033[1mwrong\033[0m way of managing data volumes\r\n"))
					err = sftp.Start()
					if err != nil {
						fail(err)
					} else {
						go func() {
							fail(sftp.Wait())
						}()
					}
				default:
					fail(req.Reply(false, nil))
				}
			case "shell":
				if tty {
					connection.Stderr().Write([]byte("\033[0mgithub.com/kmeaw/wrongssh  *  a \033[1mwrong\033[0m way of managing containers\r\n"))
				}
				fallthrough
			case "exec":
				if len(req.Payload) > 4 {
					pllen := binary.BigEndian.Uint32(req.Payload)
					pl := string(req.Payload[4 : pllen+4])
					cmd = append(cmd[0:len(cmd)-1], "-c", pl)
					log.Printf("req = %#v.\n", string(req.Payload))
				}
				req.Reply(true, nil)

				go func() {
					// Fire up bash for this session
					var err error
					log.Printf("Running %v.\n", cmd)
					execReq, err = rcli.CreateExec(docker.CreateExecOptions{
						AttachStdin:  true,
						AttachStdout: true,
						AttachStderr: true,
						Tty:          tty,
						Cmd:          cmd,
						Container:    sshConn.Permissions.Extensions["container_id"],
					})

					if err != nil {
						fail(err)
						return
					}

					success := make(chan struct{})

					go func() {
						for range success {
							success <- struct{}{}
							log.Println("Success hit!")
							if w*h > 0 {
								log.Printf("Setting window size to %dx%d.\n", w, h)
								_ = rcli.ResizeExecTTY(execReq.ID, h, w)
							} else {
								log.Println("Raced success.")
							}
						}
					}()

					err = rcli.StartExec(execReq.ID, docker.StartExecOptions{
						Detach:       false,
						Tty:          true, // tty,
						InputStream:  connection,
						OutputStream: connection,
						ErrorStream:  connection.Stderr(),
						RawTerminal:  true, // tty,
						Success:      success,
					})

					close(success)
					fail(err)
				}()
			case "pty-req":
				termLen := binary.BigEndian.Uint32(req.Payload)
				term := string(req.Payload[4 : termLen+4])
				cmd = append([]string{"/usr/bin/env", "TERM=" + term}, cmd[1:]...)
				w, h = parseDims(req.Payload[termLen+4:])
				if execReq != nil {
					_ = rcli.ResizeExecTTY(execReq.ID, h, w)
				}
				tty = true
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				w, h := parseDims(req.Payload)
				if execReq != nil {
					log.Printf("Requesting window size change to %dx%d: %#v.\n",
						w, h, rcli.ResizeExecTTY(execReq.ID, h, w))
				} else {
					log.Println("window-change during empty execReq")
				}
			default:
				log.Printf("Strange req: %#v.\n", req)
				req.Reply(false, nil)
			}
		}
		log.Println("Out of requests.")
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (int, int) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return int(w), int(h)
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
