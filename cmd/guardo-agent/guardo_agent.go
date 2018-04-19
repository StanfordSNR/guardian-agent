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

func handleOpen(dirFd *ga.DirFd, path string, flags int32, mode int32) (*ga.Fd, error) {
	fd, err := ga.OpenNoFollow(int(dirFd.GetFd()), path, int(flags), uint32(mode))
	if err != nil {
		return nil, err
	}
	return &ga.Fd{Fd: int32(fd)}, nil
}

func handleMkdir(dirFd *ga.DirFd, path string, mode int32) error {
	return ga.MkdirNoFollow(int(dirFd.GetFd()), path, uint32(mode))
}

func handleSymlinkAt(target string, dirFd *ga.DirFd, path string) error {
	return ga.SymlinkNoFollow(target, int(dirFd.GetFd()), path)
}

func handleSymlink(dirFd *ga.DirFd, target string, path string) error {
	return handleSymlinkAt(target, dirFd, path)
}

func handleUnlinkAt(dirFd *ga.DirFd, path string, flags int32) error {
	return ga.UnlinkNoFollow(int(dirFd.GetFd()), path, int(flags))
}

func handleUnlink(dirFd *ga.DirFd, path string) error {
	return ga.UnlinkNoFollow(int(dirFd.GetFd()), path, 0)
}

func handleRmdir(dirFd *ga.DirFd, path string) error {
	return ga.UnlinkNoFollow(int(dirFd.GetFd()), path, unix.AT_REMOVEDIR)
}

func handleAccess(dirFd *ga.DirFd, path string, mode int32) error {
	return ga.AccessNoFollow(int(dirFd.GetFd()), path, uint32(mode))
}

func handleFstatat(dirFd *ga.DirFd, path string, statbuf []byte, flags int32) error {
	return ga.StatNoFollow(int(dirFd.GetFd()), path, (*unix.Stat_t)(unsafe.Pointer(&statbuf[0])), int(flags))
}

func handleStat(dirFd *ga.DirFd, path string, statbuf []byte) error {
	return handleFstatat(dirFd, path, statbuf, 0)
}

func handleLstat(dirFd *ga.DirFd, path string, statbuf []byte) error {
	return handleFstatat(dirFd, path, statbuf, unix.AT_SYMLINK_NOFOLLOW)
}

func handleFstat(fd *ga.Fd, statbuf []byte) error {
	return syscall.Fstat(int(fd.GetFd()), (*syscall.Stat_t)(unsafe.Pointer(&statbuf[0])))
}

func handleReadlink(dirFd *ga.DirFd, path string, buf []byte, bufSize int32) (int, error) {
	return ga.ReadlinkNoFollow(int(dirFd.GetFd()), path, buf, int(bufSize))
}

func handleRenameAt2(oldDirFd *ga.DirFd, oldPath string, newDirFd *ga.DirFd, newPath string, flags int32) error {
	return ga.RenameNoFollow(int(oldDirFd.GetFd()), oldPath, int(newDirFd.GetFd()), newPath, int(flags))
}

func handleRenameAt(oldDirFd *ga.DirFd, oldPath string, newDirFd *ga.DirFd, newPath string) error {
	return handleRenameAt2(oldDirFd, oldPath, newDirFd, newPath, 0)
}

func handleRename(dirFd *ga.DirFd, oldPath string, newPath string) error {
	return handleRenameAt2(dirFd, oldPath, dirFd, newPath, 0)
}

func handleSocket(domain int32, typeArg int32, protocol int32) (*ga.Fd, error) {
	fd, err := unix.Socket(int(domain), int(typeArg), int(protocol))
	if err != nil {
		return nil, err
	}
	return &ga.Fd{Fd: int32(fd)}, nil
}

func handleBind(sock *ga.Fd, addr []byte, addrlen int32) error {
	_, _, err := syscall.Syscall(syscall.SYS_BIND, uintptr(sock.Fd), uintptr(unsafe.Pointer(&addr[0])), uintptr(len(addr)))
	if err != 0 {
		return err
	}
	return nil
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

	pk, err := ssh.ParsePublicKey(cred.GetSignatureKey())
	if err != nil {
		return fmt.Errorf("Failed to parse credential public key: %s", err)
	}
	if !guardo.authorizedKeys[string(cred.GetSignatureKey())] {
		return fmt.Errorf("Unauthorized public key (%s)", pk.Type())
	}

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

func writeElevationResponse(c *net.UnixConn, resp *ga.ElevationResponse, fds []int) error {
	header := make([]byte, 5)
	data, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("Failed to Marshal response %s: %s", resp, err)
	}

	binary.BigEndian.PutUint32(header, uint32(len(data)+1))
	header[4] = byte(ga.MsgNum_ELEVATION_RESPONSE)
	rights := unix.UnixRights(fds...)
	_, _, err = c.WriteMsgUnix(append(header[:], data[:]...), rights, nil)
	if err != nil {
		return fmt.Errorf("Failed to WriteMsgUnix: %s", err)
	}
	return nil
}

func readRequest(c *net.UnixConn, expectedMsgNum ga.MsgNum, pb proto.Message) (fd []int, err error) {
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
	return fds, nil
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
	fds := []int{}
	if fds, err = readRequest(c, ga.MsgNum_ELEVATION_REQUEST, elevReq); err != nil {
		return errors.Wrapf(err, "Failed to read elevation request")
	}
	for _, fd := range fds {
		defer syscall.Close(fd)
	}

	fmt.Fprintf(os.Stderr, "Requested syscall: %d\n", elevReq.GetOp().GetSyscallNum())

	if err := guardo.checkCredential(elevReq, challenge); err != nil {
		return fmt.Errorf("Credentials error: %s", err)
	}

	fmt.Fprintln(os.Stderr, "Credentials OK")

	handler, err := guardo.getRequestHandler(elevReq.GetOp(), fds)
	if err != nil {
		writeElevationResponse(c, &ga.ElevationResponse{ErrnoCode: -1}, []int{})
		return err
	}
	resp, fds := handler()
	return writeElevationResponse(c, resp, fds)
}

func (guardo *guardoAgent) getRequestHandler(op *ga.Operation, fds []int) (func() (*ga.ElevationResponse, []int), error) {
	log.Printf("Requested operation: %s\n", op)

	fdPos := 0
	argList := []reflect.Value{}
	results := []reflect.Value{}
	for _, arg := range op.Args {
		switch arg := arg.Arg.(type) {
		case *ga.Argument_DirFdArg:
			if fdPos >= len(fds) {
				return nil, fmt.Errorf("Missing FD. Have only %d but want at least one more", fdPos)
			}
			fd := fds[fdPos]
			fdPos++
			if err := verifyFileDescriptorPath(fd, arg.DirFdArg.GetPath()); err != nil {
				return nil, fmt.Errorf("FD does not match path: %d, %s: %s", fd, arg.DirFdArg.GetPath(), err)
			}
			arg.DirFdArg.Form = &ga.DirFd_Fd{Fd: int32(fd)}
			argList = append(argList, reflect.ValueOf(arg.DirFdArg))
		case *ga.Argument_FdArg:
			if fdPos >= len(fds) {
				return nil, fmt.Errorf("Missing FD. Have only %d but want at least one more", fdPos)
			}
			arg.FdArg.Fd = int32(fds[fdPos])
			fdPos++
			argList = append(argList, reflect.ValueOf(arg.FdArg))
		case *ga.Argument_IntArg:
			argList = append(argList, reflect.ValueOf(arg.IntArg))
		case *ga.Argument_StringArg:
			argList = append(argList, reflect.ValueOf(arg.StringArg))
		case *ga.Argument_BytesArg:
			argList = append(argList, reflect.ValueOf(arg.BytesArg))
		case *ga.Argument_OutBufferArg:
			outBuffer := reflect.ValueOf(make([]byte, arg.OutBufferArg.Len))
			argList = append(argList, outBuffer)
			results = append(results, outBuffer)
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
	if reflect.TypeOf(handler).NumOut() < 1 || reflect.TypeOf(handler).Out(reflect.TypeOf(handler).NumOut()-1) != reflect.TypeOf((*error)(nil)).Elem() {
		return nil, fmt.Errorf("Invalid return type of handler: %s, must return error as last value", reflect.TypeOf(handler))
	}

	return func() (resp *ga.ElevationResponse, fds []int) {
		resp = &ga.ElevationResponse{}
		fds = []int{}

		retvals := reflect.ValueOf(handler).Call(argList)
		if !retvals[len(retvals)-1].IsNil() {
			err := retvals[len(retvals)-1].Interface().(syscall.Errno)
			resp.ErrnoCode = int32(err)
			fmt.Fprintf(os.Stderr, "Syscall failed: %s\n", err)
			return
		}
		fmt.Fprintln(os.Stderr, "Syscall succeeded")

		results = append(retvals[0:len(retvals)-1], results...)

		for _, result := range results {
			switch result.Type() {
			case reflect.TypeOf(&ga.Fd{}):
				resp.Results = append(resp.Results, &ga.Argument{&ga.Argument_FdArg{result.Interface().(*ga.Fd)}})
				fds = append(fds, int(result.Interface().(*ga.Fd).Fd))
				break
			case reflect.TypeOf(int32(0)):
				fallthrough
			case reflect.TypeOf(int(0)):
				resp.Results = append(resp.Results, &ga.Argument{&ga.Argument_IntArg{int32(result.Int())}})
				break
			case reflect.TypeOf([]byte{}):
				resp.Results = append(resp.Results, &ga.Argument{&ga.Argument_BytesArg{result.Bytes()}})
			}
		}

		return
	}, nil
}

var handlerRegistry = map[int32]interface{}{
	syscall.SYS_OPENAT:     handleOpen,
	syscall.SYS_OPEN:       handleOpen,
	syscall.SYS_MKDIR:      handleMkdir,
	syscall.SYS_MKDIRAT:    handleMkdir,
	syscall.SYS_SYMLINK:    handleSymlink,
	syscall.SYS_SYMLINKAT:  handleSymlinkAt,
	syscall.SYS_UNLINK:     handleUnlink,
	syscall.SYS_UNLINKAT:   handleUnlinkAt,
	syscall.SYS_RMDIR:      handleRmdir,
	syscall.SYS_ACCESS:     handleAccess,
	syscall.SYS_FACCESSAT:  handleAccess,
	syscall.SYS_NEWFSTATAT: handleFstatat,
	syscall.SYS_LSTAT:      handleLstat,
	syscall.SYS_STAT:       handleStat,
	syscall.SYS_FSTAT:      handleFstat,
	syscall.SYS_READLINKAT: handleReadlink,
	syscall.SYS_READLINK:   handleReadlink,
	ga.SYS_RENAMEAT2:       handleRenameAt2,
	syscall.SYS_RENAMEAT:   handleRenameAt,
	syscall.SYS_RENAME:     handleRename,
	syscall.SYS_SOCKET:     handleSocket,
	syscall.SYS_BIND:       handleBind,
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
		log.Printf("Authorized key: %s \n", pubKey.Type())
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

	conf, _ := ga.GetSyscallConfig()
	names := []string{}
	if conf != nil {
		for _, spec := range conf.Syscall {
			names = append(names, spec.GetName())
		}
	}
	log.Printf("Loaded handlers for %v\n", names)

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
			ucred := ga.GetUcred(c)
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
