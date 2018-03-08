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

func handleOpen(req *ga.OpenOp, dirfd *int, ucred *syscall.Ucred) *ga.ElevationResponse {
	flags := int(req.GetFlags())
	fd, err := ga.OpenNoLinks(req.GetPath().GetFilePath(), flags, uint32(req.GetMode()))
	if err != nil {
		log.Printf("Failed to open: %s", err)
		return &ga.ElevationResponse{Result: fd}
	}
	return &ga.ElevationResponse{IsResultFd: true, Result: fd}
}

func handleUnlink(req *ga.UnlinkOp, dirfd *int) *ga.ElevationResponse {
	var err error
	if dirfd == nil {
		err = unix.Unlinkat(unix.AT_FDCWD, req.GetPath().GetFilePath(), int(req.GetFlags()))
	} else {
		err = unix.Unlinkat(*dirfd, req.GetPath().GetFilePath(), int(req.GetFlags()))
	}

	if err != nil {
		return &ga.ElevationResponse{Result: -int32(err.(syscall.Errno))}
	}
	return &ga.ElevationResponse{Result: 0}
}

func handleAccess(req *ga.AccessOp, dirfd *int) *ga.ElevationResponse {
	var err error
	if dirfd == nil {
		err = unix.Faccessat(unix.AT_FDCWD, req.GetPath().GetFilePath(), req.GetMode(), int(req.GetFlags()))
	} else {
		err = unix.Faccessat(*dirfd, req.GetPath().GetFilePath(), req.GetMode(), int(req.GetFlags()))
	}
	if err != nil {
		return &ga.ElevationResponse{Result: -int32(err.(syscall.Errno))}
	}
	return &ga.ElevationResponse{Result: 0}
}

func handleSocket(req *ga.SocketOp) *ga.ElevationResponse {
	fd, err := unix.Socket(int(req.GetDomain()), int(req.GetType()), int(req.GetProtocol()))
	if err != nil {
		return &ga.ElevationResponse{Result: -int32(err.(syscall.Errno))}
	}
	return &ga.ElevationResponse{IsResultFd: true, Result: int32(fd)}
}

func handleBind(req *ga.BindOp, fd *int) *ga.ElevationResponse {
	if fd == nil {
		return &ga.ElevationResponse{Result: -int32(unix.EBADF)}
	}
	_, _, err := syscall.Syscall(syscall.SYS_BIND, uintptr(*fd), uintptr(unsafe.Pointer(&req.GetAddr()[0])), uintptr(len(req.GetAddr())))
	if err != 0 {
		return &ga.ElevationResponse{Result: -int32(err)}
	}
	return &ga.ElevationResponse{Result: 0}
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
		fmt.Fprintf(os.Stderr, "<<< Returning file descriptor: %d\n", resp.Result)
	} else {
		fmt.Fprintf(os.Stderr, "<<< Returning result: %d (%s)\n",
			resp.Result, syscall.Errno(-resp.Result).Error())
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
	ucred := getUcred(c)
	fmt.Fprintf(os.Stderr, "\n>>> Got connection from uid: %d, pid: %d\n", ucred.Uid, ucred.Pid)

	challengeReq := &ga.ChallengeRequest{}
	if _, err := readRequest(c, ga.MsgNum_CHALLENGE_REQUEST, challengeReq); err != nil {
		return err
	}

	challenge, err := guardo.generateChallenge()
	if err != nil {
		return err
	}

	respBytes, err := proto.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("Failed to serialize challenge: %s", err)
	}
	if err := ga.WriteControlPacket(c, ga.MsgNum_CHALLENGE_RESPONSE, respBytes); err != nil {
		return fmt.Errorf("Failed to write challenge response: %s", err)
	}

	elevReq := &ga.ElevationRequest{}
	fd := new(int)
	if fd, err = readRequest(c, ga.MsgNum_ELEVATION_REQUEST, elevReq); err != nil {
		return err
	}
	if fd != nil {
		defer syscall.Close(*fd)
	}

	op := elevReq.GetOp()
	fmt.Fprintf(os.Stderr, "Requested operation: %s\n", op)

	resp := &ga.ElevationResponse{}
	if err := guardo.checkCredential(elevReq, challenge); err != nil {
		resp.Result = -int32(unix.EACCES)
		writeElevationResponse(c, resp)
		return fmt.Errorf("Credentials error: %s", err)
	}

	fmt.Fprintln(os.Stderr, "Credentials OK")

	switch op := op.Op.(type) {
	case *ga.Operation_Open:
		resp = handleOpen(op.Open, fd, ucred)
	case *ga.Operation_Unlink:
		resp = handleUnlink(op.Unlink, fd)
	case *ga.Operation_Access:
		resp = handleAccess(op.Access, fd)
	case *ga.Operation_Socket:
		resp = handleSocket(op.Socket)
	case *ga.Operation_Bind:
		resp = handleBind(op.Bind, fd)
	default:
		return fmt.Errorf("Unknown sycall request type")
	}

	return writeElevationResponse(c, resp)
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
			if err = guardo.handleConnection(c); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			c.Close()
		}()
	}
}
