// +build linux

package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"syscall"

	"github.com/StanfordSNR/guardian-agent"

	"github.com/StanfordSNR/guardian-agent/guardo"
	"github.com/dixonwille/wmenu"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func AskApproval(prompt string) bool {
	menu := wmenu.NewMenu(fmt.Sprintf("Allow %s?", prompt))
	menu.IsYesNo(1)
	isApproved := false
	menu.Action(
		func(opts []wmenu.Opt) error {
			isApproved = (opts[0].ID == 0)
			return nil
		})
	err := menu.Run()
	if err != nil {
		log.Fatal(err)
	}
	return isApproved
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
	log.Printf("flags: %d", flags)
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

func checkCredential(op *guardo.Operation, cred *guardo.Credential) error {
	if !proto.Equal(op, cred.GetOp()) {
		return fmt.Errorf("Credential does not match requested operation, requested: %v, credential for: %v", op, cred.GetOp())
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

func HandleConnection(c *net.UnixConn) {
	fmt.Println("Got connection")
	msgNum, payload, err := guardianagent.ReadControlPacket(c)
	if err != nil || msgNum != guardianagent.MsgNum_ELEVATION_REQUEST {
		log.Printf("Invalid request, msgNum: %d: %s", msgNum, err)
		return
	}
	req := &guardo.ElevationRequest{}
	if err := proto.Unmarshal(payload, req); err != nil {
		log.Fatalln("Failed to parse request:", err)
	}
	op := req.GetOp()

	resp := &guardo.ElevationResponse{}
	if err = checkCredential(op, req.GetCredential()); err != nil {
		log.Printf("Credentials error: %s", err)
		resp.Result = int32(unix.EACCES)
		payload, _ := proto.Marshal(resp)
		guardianagent.WriteControlPacket(c, guardianagent.MsgNum_ELEVATION_RESPONSE, payload)
		return
	}

	var fds []int
	switch op := op.Op.(type) {
	case *guardo.Operation_Open:
		resp, fds = HandleOpen(op.Open, getUcred(c))
	case *guardo.Operation_Unlink:
		resp = HandleUnlink(op.Unlink)
	case *guardo.Operation_Access:
		resp = HandleAccess(op.Access)
	default:
		log.Printf("Unknown sycall request type")
	}
	header := make([]byte, 5)
	data, err := proto.Marshal(resp)
	if err != nil {
		log.Fatalf("Failed to Marshal response: %s", err)
	}
	binary.LittleEndian.PutUint32(header, uint32(len(data)+1))
	header[4] = byte(guardianagent.MsgNum_ELEVATION_RESPONSE)
	rights := unix.UnixRights(fds...)
	n, _, err := c.WriteMsgUnix(append(header[:], data[:]...), rights, nil)
	if err != nil {
		log.Fatalf("Failed to WriteMsgUnix: %s", err)
	}
	log.Printf("Wrote response of len: %d and %d fds", n, len(fds))

}

func main() {
	fmt.Println("Hello")

	sockPath := path.Join("/tmp", ".guardo-sock")
	if _, err := os.Lstat(sockPath); err == nil {
		err = os.Remove(sockPath)
		if err != nil {
			log.Printf("Failed to remove old permanent socket: %s", err)
			os.Exit(255)
		}
	}
	unixAddr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		log.Printf("Failed to reslve unix addr: %s", err)
	}
	s, err := net.ListenUnix("unix", unixAddr)
	defer os.Remove(sockPath)
	os.Chmod(sockPath, os.ModePerm)

	for {
		c, err := s.AcceptUnix()
		if err != nil {
			log.Printf("Error accepting connection: %s", err)
			os.Exit(255)
		}
		go func() {
			HandleConnection(c)
		}()
	}
}
