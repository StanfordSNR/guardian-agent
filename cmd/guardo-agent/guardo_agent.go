// +build linux

package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"syscall"

	"github.com/StanfordSNR/guardian-agent"
	flags "github.com/jessevdk/go-flags"

	"github.com/StanfordSNR/guardian-agent/guardo"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

type options struct {
	Debug bool `long:"debug" description:"Show debug information"`

	LogFile string `long:"log" description:"log file"`

	Version bool `long:"version" short:"V" description:"Display the version number and exit"`

	AuthorizedKeys string `long:"authorized_keys" description:"Authorized Keys file" default:"/etc/security/authorized_keys"`
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

func createOrOpen(req *guardo.OpenOp, cred *syscall.Ucred) (int, error) {
	flags := int(req.GetFlags())
	if (cred != nil) && (flags&os.O_CREATE != 0) {
		// First try to create a new file if it doesn't exist
		fd, err := unix.Open(req.GetPath(), flags|os.O_EXCL, uint32(req.GetMode()))
		if err == nil {
			// Change the owner of the file to be the user
			if chownErr := os.Chown(req.GetPath(), int(cred.Uid), int(cred.Gid)); chownErr != nil {
				log.Printf("Failed to chown newly created file to user: %s", chownErr)
			}
			log.Printf("Created %s and chowned to %d", req.GetPath(), cred.Uid)
			return fd, err
		}
		if flags&os.O_EXCL != 0 {
			// If the original call was with O_EXCL then there's no need to retry
			return fd, err
		}
	}
	return unix.Open(req.GetPath(), flags, uint32(req.GetMode()))
}

func HandleOpen(req *guardo.OpenOp, cred *syscall.Ucred) (res *guardo.ElevationResponse, fds []int) {
	fd, err := createOrOpen(req, cred)
	if err != nil {
		log.Printf("open failed: %s", err)
		return &guardo.ElevationResponse{Result: int32(err.(syscall.Errno))}, nil
	}
	return &guardo.ElevationResponse{IsResultFd: true}, []int{fd}
}

func HandleUnlink(req *guardo.UnlinkOp) *guardo.ElevationResponse {
	err := unix.Unlinkat(unix.AT_FDCWD, req.GetPath(), int(req.GetFlags()))
	if err != nil {
		log.Printf("unlink failed: %s", err)
		return &guardo.ElevationResponse{Result: int32(err.(syscall.Errno))}
	}
	return &guardo.ElevationResponse{Result: 0}
}

func HandleAccess(req *guardo.AccessOp) *guardo.ElevationResponse {
	err := unix.Access(req.GetPath(), req.GetMode())
	if err != nil {
		log.Printf("access failed: %s", err)
		return &guardo.ElevationResponse{Result: int32(err.(syscall.Errno))}
	}
	return &guardo.ElevationResponse{Result: 0}
}

func checkCredential(op *guardo.Operation, cred *guardo.Credential, authKeys map[string]bool) error {
	if !proto.Equal(op, cred.GetOp()) {
		return fmt.Errorf("Credential does not match requested operation, requested: %v, credential for: %v", op, cred.GetOp())
	}
	if !authKeys[string(cred.GetSignatureKey())] {
		return fmt.Errorf("Unauthorized public key")
	}

	pk, err := ssh.ParsePublicKey(cred.GetSignatureKey())
	cred_no_sig := *cred
	cred_no_sig.Signature = nil
	cred_no_sig.SignatureFormat = ""
	byte_to_sign, err := proto.Marshal(&cred_no_sig)
	if err != nil {
		return err
	}
	sig := &ssh.Signature{
		Format: cred.SignatureFormat,
		Blob:   cred.Signature,
	}

	return pk.Verify(byte_to_sign, sig)
}

func HandleConnection(c *net.UnixConn, authKeys map[string]bool) error {
	ucred := getUcred(c)
	fmt.Printf("\n>>> Got connection from uid: %d, pid: %d\n", ucred.Uid, ucred.Pid)
	msgNum, payload, err := guardianagent.ReadControlPacket(c)
	if err != nil || msgNum != guardianagent.MsgNum_ELEVATION_REQUEST {
		return fmt.Errorf("Invalid request, msgNum: %d: %s", msgNum, err)
	}
	req := &guardo.ElevationRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		return fmt.Errorf("Failed to parse request: %s", err)
	}
	op := req.GetOp()

	fmt.Printf("Requested operation: %s\n", op)

	resp := &guardo.ElevationResponse{}
	if err = checkCredential(op, req.GetCredential(), authKeys); err != nil {
		resp.Result = -int32(unix.EACCES)
		payload, _ := proto.Marshal(resp)
		guardianagent.WriteControlPacket(c, guardianagent.MsgNum_ELEVATION_RESPONSE, payload)
		return fmt.Errorf("Credentials error: %s", err)
	}

	fmt.Println("Credentials OK")

	var fds []int
	switch op := op.Op.(type) {
	case *guardo.Operation_Open:
		resp, fds = HandleOpen(op.Open, ucred)
	case *guardo.Operation_Unlink:
		resp = HandleUnlink(op.Unlink)
	case *guardo.Operation_Access:
		resp = HandleAccess(op.Access)
	default:
		return fmt.Errorf("Unknown sycall request type")
	}
	header := make([]byte, 5)
	data, err := proto.Marshal(resp)
	if err != nil {
		return fmt.Errorf("Failed to Marshal response: %s", err)
	}
	binary.BigEndian.PutUint32(header, uint32(len(data)+1))
	header[4] = byte(guardianagent.MsgNum_ELEVATION_RESPONSE)
	rights := unix.UnixRights(fds...)
	_, _, err = c.WriteMsgUnix(append(header[:], data[:]...), rights, nil)
	if err != nil {
		return fmt.Errorf("Failed to WriteMsgUnix: %s", err)
	}

	if resp.IsResultFd && len(fds) > 0 {
		fmt.Printf("<<< Returning file descriptor: %d\n", fds[0])
	} else {
		fmt.Printf("<<< Returning result: %d\n", resp.Result)
	}
	return nil
}

func main() {
	var opts options
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassDoubleDash)
	parser.UnknownOptionHandler = func(option string, arg flags.SplitArgument, args []string) ([]string, error) {
		fmt.Fprintf(os.Stderr, "Unknown option: %s\n", option)
		return args, nil
	}

	guardianagent.ParseCommandLineOrDie(parser, &opts)

	authorizedKeysBytes, err := ioutil.ReadFile(opts.AuthorizedKeys)
	if err != nil {
		fmt.Printf("Failed to load authorized_keys, err: %v\n", err)
		os.Exit(255)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(255)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	sockPath := path.Join("/tmp", ".guardo-sock")
	if _, err := os.Lstat(sockPath); err == nil {
		err = os.Remove(sockPath)
		if err != nil {
			fmt.Printf("Failed to remove old permanent socket: %s\n", err)
			os.Exit(255)
		}
	}
	unixAddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		fmt.Printf("Failed to reslve unix addr: %s", err)
	}
	s, err := net.ListenUnix("unix", unixAddr)
	defer os.Remove(sockPath)
	os.Chmod(sockPath, os.ModePerm)

	fmt.Printf("Listening on %s for incoming elevation requests...\n", unixAddr)

	for {
		c, err := s.AcceptUnix()
		if err != nil {
			fmt.Printf("Error accepting connection: %s\n", err)
			os.Exit(255)
		}
		go func() {
			if err = HandleConnection(c, authorizedKeysMap); err != nil {
				fmt.Printf("%v\n", err)
			}
		}()
	}
}
