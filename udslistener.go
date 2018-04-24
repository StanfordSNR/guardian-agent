package guardianagent

import (
	"fmt"
	"net"
	"os/user"
)

type UDSListener struct {
	*net.UnixListener
}

func (l UDSListener) Accept() (net.Conn, error) {
	client, err := l.UnixListener.AcceptUnix()
	if err != nil {
		return nil, err
	}
	ucred, err := GetUcred(client)
	if err != nil {
		return nil, fmt.Errorf("Failed to get client creds: %s", err)
	}
	user, err := user.LookupId(fmt.Sprintf("%d", ucred.Uid))
	if err != nil {
		return nil, fmt.Errorf("Failed to identify client userid: %d, %s", ucred.Uid, err)
	}
	notice := AgentForwardingNoticeMsg{ReadableName: fmt.Sprintf("%s@localhost", user.Username), Host: "localhost", Port: 22}
	return AddNotice(client, notice)
}
