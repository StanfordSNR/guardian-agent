// +build linux

package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"syscall"
	"unsafe"

	ga "github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type options struct {
	ga.CommonOptions
	AuthorizedKeys string `long:"authorized_keys" description:"Authorized Keys file" default:"/etc/security/authorized_keys"`

	PublicKey []string `long:"public_keys" description:"Server identity public key files" default:"/etc/ssh/ssh_host_dsa_key.pub" default:"/etc/ssh/ssh_host_ecdsa_key.pub" default:"/etc/ssh/ssh_host_ed25519_key.pub" default:"/etc/ssh/ssh_host_rsa_key.pub"`
}

type guardoAgent struct {
	authorizedKeys map[string]bool
	publicKeys     map[string]bool
	hostname       string
}

func (opts *options) GetVersion() bool {
	return opts.Version
}

func getUcred(conn *net.UnixConn) *syscall.Ucred {
	f, err := conn.File()
	if err != nil {
		return nil
	}
	defer f.Close()

	cred, err := syscall.GetsockoptUcred(int(f.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return nil
	}
	return cred
}

func verifyFileDescriptorPath(fd int, path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("DirFd path must be absolute")
	}
	pathFD, err := ga.OpenDirNoFollow(unix.AT_FDCWD, path)
	if err != nil {
		return err
	}
	var statPath unix.Stat_t
	err = unix.Fstat(int(pathFD), &statPath)
	if err != nil {
		return errors.Wrapf(err, "Cannot stat %s", path)
	}
	var statFd unix.Stat_t
	err = unix.Fstat(int(fd), &statFd)
	if err != nil {
		return errors.Wrapf(err, "Cannot stat fd")
	}
	if statPath.Dev == statFd.Dev && statPath.Ino == statFd.Ino {
		return nil
	}
	return fmt.Errorf("File descriptor and path differ")
}

func handleOpen(dirFd *ga.DirFd, path string, flags int32, mode int32) (*ga.ElevationResponse, error) {
	fd, err := ga.OpenNoFollow(int(dirFd.GetFd()), path, int(flags), uint32(mode))
	if err != nil {
		return nil, err
	}
	return &ga.ElevationResponse{IsResultFd: true, Result: int32(fd)}, nil
}

func handleUnlink(dirFd *ga.DirFd, path string, flags int32) (*ga.ElevationResponse, error) {
	err := ga.UnlinkNoFollow(int(dirFd.GetFd()), path, int(flags))
	if err != nil {
		return nil, err
	}
	return &ga.ElevationResponse{Result: 0}, nil
}

func handleAccess(dirFd *ga.DirFd, path string, mode int32, flags int32) (*ga.ElevationResponse, error) {
	err := ga.AccessNoFollow(int(dirFd.GetFd()), path, uint32(mode), int(flags))
	if err != nil {
		return nil, err
	}
	return &ga.ElevationResponse{Result: 0}, nil
}

func handleSocket(domain int32, typeArg int32, protocol int32) (*ga.ElevationResponse, error) {
	fd, err := unix.Socket(int(domain), int(typeArg), int(protocol))
	if err != nil {
		return nil, err
	}
	return &ga.ElevationResponse{IsResultFd: true, Result: int32(fd)}, nil
}

func handleBind(sock *ga.Socket, addr []byte) (*ga.ElevationResponse, error) {
	_, _, err := syscall.Syscall(syscall.SYS_BIND, uintptr(sock.Fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	if err != 0 {
		return nil, err
	}
	return &ga.ElevationResponse{Result: 0}, nil
}

func (guardo *guardoAgent) checkCredential(req *ga.ElevationRequest, challenge *ga.Challenge) error {
	cred := req.GetCredential()
	if !proto.Equal(req.GetOp(), cred.GetOp()) {
		return fmt.Errorf("Credential does not match requested operation, requested: %v, credential for: %v", req.GetOp(), cred.GetOp())
	}

	if cred.GetChallenge().GetServerHostname() != guardo.hostname {
		return fmt.Errorf("Invalid server hostname")
	}

	if !guardo.publicKeys[string(cred.GetChallenge().ServerPublicKeys[0])] {
		return fmt.Errorf("Invalid server public key")
	}

	if !guardo.authorizedKeys[string(cred.GetSignatureKey())] {
		return fmt.Errorf("Unauthorized public key")
	}

	pk, err := ssh.ParsePublicKey(cred.GetSignatureKey())
	credNoSig := *cred
	credNoSig.Signature = nil
	credNoSig.SignatureFormat = ""
	bytesToSign, err := proto.Marshal(&credNoSig)
	if err != nil {
		return err
	}
	sig := &ssh.Signature{
		Format: cred.SignatureFormat,
		Blob:   cred.Signature,
	}

	return pk.Verify(bytesToSign, sig)
}

func writeElevationResponse(c *net.UnixConn, resp *ga.ElevationResponse) error {
	if resp.IsResultFd {
		log.Printf("Returning file descriptor: %d", resp.Result)
	} else {
		log.Printf("Returning result: %d (%s)\n", resp.Result, syscall.Errno(-resp.Result).Error())
	}

	header := make([]byte, 5)
	data, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("Failed to Marshal response: %s", err)
	}
	binary.BigEndian.PutUint32(header, uint32(len(data)+1))
	header[4] = byte(ga.MsgNum_ELEVATION_RESPONSE)
	fds := []int{}
	if resp.IsResultFd {
		fds = append(fds, int(resp.Result))
		defer syscall.Close(int(resp.Result))
	}
	rights := unix.UnixRights(fds...)
	_, _, err = c.WriteMsgUnix(append(header[:], data[:]...), rights, nil)
	if err != nil {
		return fmt.Errorf("Failed to WriteMsgUnix: %s", err)
	}
	return nil
}

func readRequest(c *net.UnixConn, expectedMsgNum ga.MsgNum, pb proto.Message) (fd *int, err error) {
	const MaxPacketLen = 4096
	packet := make([]byte, MaxPacketLen)
	oob := make([]byte, unix.CmsgSpace(4))

	n, oobn, _, _, err := c.ReadMsgUnix(packet, oob)
	if err != nil {
		return nil, errors.Wrap(err, "ReadMsgUnix failed")
	}

	if n < 5 || n > MaxPacketLen {
		return nil, errors.Wrapf(err, "Invalid incoming-packet length (expected >=5 and <=%d): %d", MaxPacketLen, n)
	}

	packet = packet[:n]

	length := int(binary.BigEndian.Uint32(packet[0:4]))
	payload := packet[4:]
	if length != len(payload) {
		return nil, fmt.Errorf("Invalid payload length: expected: %d, got: %d", length, len(payload))
	}
	msgNum := ga.MsgNum(payload[0])
	if msgNum != expectedMsgNum {
		return nil, fmt.Errorf("Invalid request, expected: %s, got: %s", expectedMsgNum.String(), msgNum.String())
	}
	if err := proto.Unmarshal(payload[1:], pb); err != nil {
		return nil, errors.Wrapf(err, "Failed to parse request: %d", msgNum)
	}

	if oobn <= 0 {
		return nil, nil
	}

	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse socket control message")
	}

	if len(msgs) != 1 {
		return nil, fmt.Errorf("Invalid number of control messages, expected only one, got: %d", len(msgs))
	}
	fds, err := syscall.ParseUnixRights(&msgs[0])
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse unix rights")
	}
	if len(fds) != 1 {
		return nil, fmt.Errorf("Invalid number of file descriptors in control message, expected only one, got: %d", len(fds))
	}
	return &fds[0], nil
}

func (guardo *guardoAgent) generateChallenge() (*ga.Challenge, error) {
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	resp := &ga.Challenge{
		ServerNonce:    nonce,
		ServerHostname: guardo.hostname,
	}
	for pk := range guardo.publicKeys {
		resp.ServerPublicKeys = append(resp.ServerPublicKeys, []byte(pk))
	}
	return resp, nil
}

func (guardo *guardoAgent) handleConnection(c *net.UnixConn) error {
	challengeReq := &ga.ChallengeRequest{}
	if _, err := readRequest(c, ga.MsgNum_CHALLENGE_REQUEST, challengeReq); err != nil {
		return errors.Wrapf(err, "Failed to read challenge request")
	}

	challenge, err := guardo.generateChallenge()
	if err != nil {
		return errors.Wrapf(err, "Failed to generate challenge")
	}

	respBytes, err := proto.Marshal(challenge)
	if err != nil {
		return errors.Wrapf(err, "Failed to serialize challenge")
	}
	if err := ga.WriteControlPacket(c, ga.MsgNum_CHALLENGE_RESPONSE, respBytes); err != nil {
		return errors.Wrapf(err, "Failed to write challenge response")
	}

	elevReq := &ga.ElevationRequest{}
	fd := new(int)
	if fd, err = readRequest(c, ga.MsgNum_ELEVATION_REQUEST, elevReq); err != nil {
		return errors.Wrapf(err, "Failed to read elevation request")
	}
	if fd != nil {
		defer syscall.Close(*fd)
	}

	fmt.Fprintf(os.Stderr, "Requested syscall: %s\n", elevReq.GetOp().GetSyscallNum())

	if err := guardo.checkCredential(elevReq, challenge); err != nil {
		return fmt.Errorf("Credentials error: %s", err)
	}

	fmt.Fprintln(os.Stderr, "Credentials OK")

	handler, err := guardo.getRequestHandler(elevReq.GetOp(), fd)
	if err != nil {
		writeElevationResponse(c, &ga.ElevationResponse{Result: -1})
		return err
	}
	resp, err := handler()
	if err != nil {
		writeElevationResponse(c, &ga.ElevationResponse{Result: -1})
		return err
	}
	return writeElevationResponse(c, resp)
}

func (guardo *guardoAgent) getRequestHandler(op *ga.Operation, fd *int) (func() (*ga.ElevationResponse, error), error) {
	log.Printf("Requested operation: %s\n", op)

	argList := []reflect.Value{}
	for _, arg := range op.Args {
		switch arg := arg.Arg.(type) {
		case *ga.Argument_DirFdArg:
			if err := verifyFileDescriptorPath(*fd, arg.DirFdArg.GetPath()); err != nil {
				return nil, fmt.Errorf("FD does not match path: %d, %s: %s", *fd, arg.DirFdArg.GetPath(), err)
			}
			arg.DirFdArg.Form = &ga.DirFd_Fd{Fd: int32(*fd)}
			argList = append(argList, reflect.ValueOf(arg.DirFdArg))
		case *ga.Argument_SocketArg:
			arg.SocketArg.Fd = int32(*fd)
			argList = append(argList, reflect.ValueOf(arg.SocketArg))
		case *ga.Argument_IntArg:
			argList = append(argList, reflect.ValueOf(arg.IntArg))
		case *ga.Argument_StringArg:
			argList = append(argList, reflect.ValueOf(arg.StringArg))
		case *ga.Argument_BytesArg:
			argList = append(argList, reflect.ValueOf(arg.BytesArg))
		}
	}

	handler := handlerRegistry[op.SyscallNum]
	if handler == nil {
		return nil, fmt.Errorf("Unknown sycall request type")
	}
	if reflect.TypeOf(handler).Kind() != reflect.Func {
		return nil, fmt.Errorf("Invalid handler for syscall: %d", op.SyscallNum)
	}
	if reflect.TypeOf(handler).NumIn() != len(argList) {
		return nil, fmt.Errorf("Invalid number of arguments to syscall: %d, expected: %d, got %d",
			op.SyscallNum, reflect.TypeOf(handler).NumIn(), len(argList))
	}
	for i, arg := range argList {
		if arg.Type() != reflect.TypeOf(handler).In(i) {
			return nil, fmt.Errorf("Invalid argument number %d to syscall %d, expected: %v, got: %v",
				i, op.SyscallNum, reflect.TypeOf(handler).In(i), arg.Type())
		}
	}
	if reflect.TypeOf(handler).NumOut() != 2 || reflect.TypeOf(handler).Out(0) != reflect.TypeOf((*ga.ElevationResponse)(nil)) || reflect.TypeOf(handler).Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		return nil, fmt.Errorf("Invalid return type of handler: %s", reflect.TypeOf(handler))
	}
	return func() (resp *ga.ElevationResponse, err error) {
		result := reflect.ValueOf(handler).Call(argList)
		if !result[0].IsNil() {
			resp = result[0].Interface().(*ga.ElevationResponse)
		}
		if !result[1].IsNil() {
			err = result[1].Interface().(error)
		}
		return
	}, nil
}

var handlerRegistry = map[int32]interface{}{
	syscall.SYS_OPENAT:    handleOpen,
	syscall.SYS_OPEN:      handleOpen,
	syscall.SYS_UNLINK:    handleUnlink,
	syscall.SYS_UNLINKAT:  handleUnlink,
	syscall.SYS_ACCESS:    handleAccess,
	syscall.SYS_FACCESSAT: handleAccess,
	syscall.SYS_SOCKET:    handleSocket,
	syscall.SYS_BIND:      handleBind,
}

func main() {
	var opts options
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		fmt.Fprintf(os.Stderr, "Unknown option: %s\n", option)
		return args, nil
	}

	ga.ParseCommandLineOrDie(parser, &opts)

	authorizedKeysBytes, err := ioutil.ReadFile(opts.AuthorizedKeys)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load authorized_keys, err: %v\n", err)
		os.Exit(255)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(255)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	publicKeys := map[string]bool{}
	for _, pkFile := range opts.PublicKey {
		if _, err := os.Stat(pkFile); os.IsNotExist(err) {
			continue
		}
		pkBytes, err := ioutil.ReadFile(pkFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load public key, err: %v\n", err)
			os.Exit(255)
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pkBytes)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(255)
		}

		publicKeys[string(pubKey.Marshal())] = true
	}

	if len(publicKeys) == 0 {
		fmt.Fprintln(os.Stderr, "Error: did not find any server public key")
		os.Exit(255)
	}

	sockPath := path.Join("/tmp", ".guardo-sock")
	if _, err := os.Lstat(sockPath); err == nil {
		err = os.Remove(sockPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove old permanent socket: %s\n", err)
			os.Exit(255)
		}
	}
	unixAddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to reslve unix addr: %s", err)
	}
	s, err := net.ListenUnix("unix", unixAddr)
	defer os.Remove(sockPath)
	os.Chmod(sockPath, os.ModePerm)

	fmt.Fprintf(os.Stderr, "Listening on %s for incoming elevation requests...\n", unixAddr)

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve local hostname: %s\n", err)
	}
	guardo := &guardoAgent{
		hostname:       hostname,
		authorizedKeys: authorizedKeysMap,
		publicKeys:     publicKeys,
	}

	for {
		c, err := s.AcceptUnix()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error accepting connection: %s\n", err)
			os.Exit(255)
		}
		go func() {
			ucred := getUcred(c)
			var err error
			fmt.Fprintf(os.Stderr, "\n>>> Got connection from uid: %d, pid: %d\n", ucred.Uid, ucred.Pid)
			err = guardo.handleConnection(c)
			if err != nil {
				fmt.Fprintf(os.Stderr, "<<< Connection finished with error: %s\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "<<< Connection finished OK\n")
			}

			c.Close()
		}()
	}
}
