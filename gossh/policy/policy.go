package policy

import (
    "bufio"
    "os"
    "errors"
    "log"
    "strings"
)

type Policy struct {
    User    string
    Command string
    Server  string
}

func NewPolicy(username string, host string, cmd string) *Policy {
    return &Policy{
        User:    username,
        Command: cmd,
        Server:  host,
    }
}

func (pc *Policy) ValidatePolicy() error{
    reader := bufio.NewReader(os.Stdin)
    var text string
    // switch to regex
    for text != "y" && text != "n" {
        log.Printf("\nApprove '%s' on %s by %s? [y/n]:\n", pc.Command, pc.Server, pc.User)
        text, _ = reader.ReadString('\n')
        text = strings.ToLower(strings.Trim(text," \r\n"))
    }

    var err error
    if text == "n" {
        err = errors.New("Policy rejected client request")
    }
    return err
}

func (pc *Policy) VerifyCommand(cmd string) bool {
    return pc.Command == cmd
}