package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	defaultListen         = "0.0.0.0:2222"
	defaultHostKey        = "/opt/tizenpwn-ssh/etc/ssh_host_ed25519_key"
	defaultAuthorizedKeys = "/opt/tizenpwn-ssh/etc/authorized_keys"
	defaultLog            = "/opt/tizenpwn-ssh/var/sshd.log"
	defaultPIDFile        = "/opt/tizenpwn-ssh/var/sshd.pid"
	defaultUser           = "root"
	defaultShell          = "/bin/bash"
	defaultHome           = "/root"
	serverVersion         = "SSH-2.0-tizenpwn"
)

type ptyRequest struct {
	Term          string
	Columns       uint32
	Rows          uint32
	Width         uint32
	Height        uint32
	TerminalModes string
}

type windowChange struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

type execRequest struct {
	Command string
}

type subsystemRequest struct {
	Subsystem string
}

type signalRequest struct {
	Signal string
}

type exitStatus struct {
	Status uint32
}

type server struct {
	user        string
	shell       string
	home        string
	logger      *log.Logger
	logCommands bool
}

func main() {
	listen := flag.String("listen", defaultListen, "listen address")
	hostKey := flag.String("host-key", defaultHostKey, "OpenSSH/PEM host private key")
	authorizedKeys := flag.String(
		"authorized-keys",
		defaultAuthorizedKeys,
		"authorized_keys file",
	)
	logPath := flag.String("log", defaultLog, "log file, or - for stderr")
	logMaxBytes := flag.Int64(
		"log-max-bytes",
		1048576,
		"rotate the log at this size; 0 disables rotation",
	)
	pidPath := flag.String("pid-file", defaultPIDFile, "pid file, or empty")
	user := flag.String("user", defaultUser, "only this SSH user is allowed")
	shell := flag.String("shell", defaultShell, "login shell")
	home := flag.String("home", defaultHome, "session home directory")
	generateHostKey := flag.Bool(
		"generate-host-key",
		false,
		"create an Ed25519 host key if the file is missing",
	)
	logCommands := flag.Bool(
		"log-commands",
		false,
		"include exec command strings in the log",
	)
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println("tizenpwn-sshd 0.1.0")
		return
	}

	logger, closeLog, err := openLog(*logPath, *logMaxBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer closeLog()

	signer, err := loadHostKey(*hostKey, *generateHostKey)
	if err != nil {
		logger.Printf("host key error: %v", err)
		os.Exit(1)
	}
	keys, err := loadAuthorizedKeys(*authorizedKeys)
	if err != nil {
		logger.Printf("authorized keys error: %v", err)
		os.Exit(1)
	}
	if err := os.Chdir("/"); err != nil {
		logger.Printf("chdir error: %v", err)
		os.Exit(1)
	}

	config := &ssh.ServerConfig{
		ServerVersion: serverVersion,
		MaxAuthTries:  6,
		PublicKeyCallback: func(
			conn ssh.ConnMetadata,
			key ssh.PublicKey,
		) (*ssh.Permissions, error) {
			if conn.User() != *user {
				return nil, fmt.Errorf("user %q is not allowed", conn.User())
			}
			if _, isCertificate := key.(*ssh.Certificate); isCertificate {
				return nil, errors.New("certificate keys are not accepted")
			}
			for _, allowed := range keys {
				if bytes.Equal(allowed.Marshal(), key.Marshal()) {
					fingerprint := ssh.FingerprintSHA256(key)
					return &ssh.Permissions{
						Extensions: map[string]string{
							"fingerprint": fingerprint,
						},
					}, nil
				}
			}
			return nil, errors.New("public key is not authorized")
		},
	}
	config.AddHostKey(signer)

	instance := &server{
		user:        *user,
		shell:       *shell,
		home:        *home,
		logger:      logger,
		logCommands: *logCommands,
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Printf("listen error: %v", err)
		os.Exit(1)
	}
	defer listener.Close()
	if err := writePIDFile(*pidPath); err != nil {
		logger.Printf("pid file error: %v", err)
		os.Exit(1)
	}
	if *pidPath != "" {
		defer os.Remove(*pidPath)
	}
	logger.Printf(
		"listening on %s as %s; host key %s; %d authorized key(s)",
		listener.Addr(),
		*user,
		ssh.FingerprintSHA256(signer.PublicKey()),
		len(keys),
	)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		logger.Printf("shutting down")
		listener.Close()
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Printf("accept error: %v", err)
			continue
		}
		go instance.handleConnection(connection, config)
	}
}

func writePIDFile(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(
		path,
		[]byte(strconv.Itoa(os.Getpid())+"\n"),
		0644,
	)
}

type rotatingWriter struct {
	path     string
	maxBytes int64
	file     *os.File
	size     int64
	mutex    sync.Mutex
}

func newRotatingWriter(path string, maxBytes int64) (*rotatingWriter, error) {
	writer := &rotatingWriter{path: path, maxBytes: maxBytes}
	if err := writer.open(); err != nil {
		return nil, err
	}
	return writer, nil
}

func (w *rotatingWriter) open() error {
	file, err := os.OpenFile(
		w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600,
	)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return err
	}
	w.file = file
	w.size = info.Size()
	return nil
}

func (w *rotatingWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	if w.maxBytes > 0 &&
		w.size > 0 &&
		w.size+int64(len(data)) > w.maxBytes {
		_ = w.file.Close()
		_ = os.Rename(w.path, w.path+".1")
		if err := w.open(); err != nil {
			return 0, err
		}
	}
	written, err := w.file.Write(data)
	w.size += int64(written)
	return written, err
}

func (w *rotatingWriter) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.file.Close()
}

func openLog(
	path string,
	maxBytes int64,
) (*log.Logger, func(), error) {
	if path == "-" {
		return log.New(os.Stderr, "", log.LstdFlags|log.LUTC), func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, nil, fmt.Errorf("create log directory: %w", err)
	}
	writer, err := newRotatingWriter(path, maxBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("open log: %w", err)
	}
	return log.New(writer, "", log.LstdFlags|log.LUTC), func() {
		_ = writer.Close()
	}, nil
}

func loadHostKey(path string, generate bool) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if err := requirePrivateFile(path); err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(data)
	}
	if !generate || !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func requirePrivateFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf(
			"%s must not be group- or world-accessible", path,
		)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if stat.Uid != uint32(os.Geteuid()) {
			return fmt.Errorf("%s must be owned by the server user", path)
		}
	}
	return nil
}

func loadAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	if err := requirePrivateFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("invalid authorized key: %w", err)
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("authorized_keys contains no keys")
	}
	return keys, nil
}

func (s *server) handleConnection(
	connection net.Conn,
	config *ssh.ServerConfig,
) {
	sshConnection, channels, requests, err := ssh.NewServerConn(
		connection, config,
	)
	if err != nil {
		s.logger.Printf("handshake failed from %s: %v", connection.RemoteAddr(), err)
		_ = connection.Close()
		return
	}
	defer sshConnection.Close()
	fingerprint := ""
	if sshConnection.Permissions != nil {
		fingerprint = sshConnection.Permissions.Extensions["fingerprint"]
	}
	s.logger.Printf(
		"login user=%s from=%s key=%s",
		sshConnection.User(),
		sshConnection.RemoteAddr(),
		fingerprint,
	)
	go ssh.DiscardRequests(requests)
	for channel := range channels {
		if channel.ChannelType() != "session" {
			_ = channel.Reject(ssh.UnknownChannelType, "only session is allowed")
			continue
		}
		session, sessionRequests, err := channel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(session, sessionRequests)
	}
}

func (s *server) handleSession(
	session ssh.Channel,
	requests <-chan *ssh.Request,
) {
	defer session.Close()

	var (
		term         string
		columns      uint32 = 80
		rows         uint32 = 24
		ptyRequested bool
		started      bool
		mutex        sync.Mutex
		ptyFile      *os.File
		process      *exec.Cmd
	)

	setPTY := func(file *os.File) {
		mutex.Lock()
		ptyFile = file
		mutex.Unlock()
	}
	getPTY := func() *os.File {
		mutex.Lock()
		defer mutex.Unlock()
		return ptyFile
	}
	setProcess := func(command *exec.Cmd) {
		mutex.Lock()
		process = command
		mutex.Unlock()
	}
	getProcess := func() *exec.Cmd {
		mutex.Lock()
		defer mutex.Unlock()
		return process
	}

	for request := range requests {
		switch request.Type {
		case "pty-req":
			var value ptyRequest
			if err := ssh.Unmarshal(request.Payload, &value); err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			ptyRequested = true
			term = value.Term
			columns = value.Columns
			rows = value.Rows
			_ = request.Reply(true, nil)
		case "window-change":
			var value windowChange
			if err := ssh.Unmarshal(request.Payload, &value); err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			columns = value.Columns
			rows = value.Rows
			if columns == 0 {
				columns = 80
			}
			if rows == 0 {
				rows = 24
			}
			if file := getPTY(); file != nil {
				_ = pty.Setsize(file, &pty.Winsize{
					Rows: uint16(rows),
					Cols: uint16(columns),
				})
			}
			_ = request.Reply(true, nil)
		case "env":
			// Client environment is ignored deliberately. The server supplies
			// a fixed root environment; the only client-controlled value is
			// TERM from pty-req.
			_ = request.Reply(false, nil)
		case "shell":
			if started {
				_ = request.Reply(false, nil)
				continue
			}
			started = true
			_ = request.Reply(true, nil)
			command := exec.Command(s.shell, "-l")
			go s.startCommand(
				session,
				command,
				ptyRequested,
				term,
				columns,
				rows,
				setPTY,
				setProcess,
			)
		case "exec":
			if started {
				_ = request.Reply(false, nil)
				continue
			}
			var value execRequest
			if err := ssh.Unmarshal(request.Payload, &value); err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			started = true
			_ = request.Reply(true, nil)
			if s.logCommands {
				s.logger.Printf("exec: %s", value.Command)
			}
			command := exec.Command(s.shell, "-c", value.Command)
			go s.startCommand(
				session,
				command,
				ptyRequested,
				term,
				columns,
				rows,
				setPTY,
				setProcess,
			)
		case "subsystem":
			if started {
				_ = request.Reply(false, nil)
				continue
			}
			var value subsystemRequest
			if err := ssh.Unmarshal(request.Payload, &value); err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			if value.Subsystem != "sftp" {
				_ = request.Reply(false, nil)
				continue
			}
			started = true
			_ = request.Reply(true, nil)
			go s.runSFTP(session)
		case "signal":
			var value signalRequest
			if err := ssh.Unmarshal(request.Payload, &value); err == nil {
				if command := getProcess(); command != nil &&
					command.Process != nil {
					_ = command.Process.Signal(signalByName(value.Signal))
				}
			}
			_ = request.Reply(true, nil)
		default:
			_ = request.Reply(false, nil)
		}
	}
}

func (s *server) startCommand(
	session ssh.Channel,
	command *exec.Cmd,
	ptyRequested bool,
	term string,
	columns uint32,
	rows uint32,
	setPTY func(*os.File),
	setProcess func(*exec.Cmd),
) {
	setProcess(command)
	command.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + s.home,
		"USER=" + s.user,
		"LOGNAME=" + s.user,
		"SHELL=" + s.shell,
		"LANG=C",
		"TERM=" + term,
		"HISTFILE=/dev/null",
	}
	command.Dir = s.home

	var waitError error
	if ptyRequested {
		if columns == 0 {
			columns = 80
		}
		if rows == 0 {
			rows = 24
		}
		file, err := pty.Start(command)
		if err != nil {
			s.logger.Printf("pty start error: %v", err)
			sendExitStatus(session, 1)
			return
		}
		setPTY(file)
		_ = pty.Setsize(file, &pty.Winsize{
			Rows: uint16(rows),
			Cols: uint16(columns),
		})
		go func() {
			// A client EOF on stdin is normal for `ssh -tt host command`;
			// it must not close the PTY and kill the running command. Only a
			// read error (disconnect) tears the PTY down.
			if _, err := io.Copy(file, session); err != nil {
				_ = file.Close()
			}
		}()
		_, _ = io.Copy(session, file)
		waitError = command.Wait()
		_ = file.Close()
	} else {
		command.Stdin = session
		command.Stdout = session
		command.Stderr = session.Stderr()
		waitError = command.Run()
	}

	status := 0
	if waitError != nil {
		var exitError *exec.ExitError
		if errors.As(waitError, &exitError) {
			status = exitError.ExitCode()
		} else {
			status = 1
		}
	}
	sendExitStatus(session, status)
}

func (s *server) runSFTP(session ssh.Channel) {
	server, err := sftp.NewServer(session)
	if err != nil {
		s.logger.Printf("sftp server error: %v", err)
		sendExitStatus(session, 1)
		return
	}
	defer server.Close()
	status := 0
	if err := server.Serve(); err != nil && !errors.Is(err, io.EOF) {
		s.logger.Printf("sftp session error: %v", err)
		status = 1
	}
	sendExitStatus(session, status)
}

func sendExitStatus(session ssh.Channel, status int) {
	_, _ = session.SendRequest(
		"exit-status",
		false,
		ssh.Marshal(exitStatus{Status: uint32(status)}),
	)
	_ = session.Close()
}

func signalByName(name string) os.Signal {
	switch strings.ToUpper(strings.TrimPrefix(name, "SIG")) {
	case "TERM":
		return syscall.SIGTERM
	case "KILL":
		return syscall.SIGKILL
	case "INT":
		return syscall.SIGINT
	case "HUP":
		return syscall.SIGHUP
	case "QUIT":
		return syscall.SIGQUIT
	default:
		return syscall.SIGTERM
	}
}
