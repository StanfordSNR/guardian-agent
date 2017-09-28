package common

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/howeyc/gopass"
	i "github.com/sternhenri/interact"
)

type Interact interface {
	Ask(prompt Prompt) (int, error)
	Inform(msg string)
	AskPassword(msg string) ([]byte, error)
}

type Terminal struct{}
type FancyTerminal struct{}
type AskPass struct{}

type Prompt struct {
	Question string
	Choices  []string
}

func (Terminal) Ask(params Prompt) (reply int, err error) {
	reply = -1
	var convErr error

	for convErr != nil || reply <= 0 || reply > len(params.Choices) {
		fmt.Print(formatPrompt(params))
		reader := bufio.NewReader(os.Stdin)
		sReply, _ := reader.ReadString('\n')
		reply, convErr = strconv.Atoi(strings.TrimSpace(sReply))
	}

	return
}

func (Terminal) Inform(msg string) {
	fmt.Println(msg)
}

func (Terminal) AskPassword(msg string) ([]byte, error) {
	fmt.Println(msg)
	return gopass.GetPasswd()
}

func formatPrompt(params Prompt) (formattedPrompt string) {
	var buf bytes.Buffer
	buf.WriteString(params.Question)
	for i, v := range params.Choices {
		buf.WriteString(fmt.Sprintf("\n    %d) %s", i+1, v))
	}
	buf.WriteString("\n\nAnswer (enter a number): ")
	formattedPrompt = buf.String()
	return
}

func mapToChoice(vs []string) []i.Choice {
	vsm := make([]i.Choice, len(vs))
	for j, v := range vs {
		vsm[j] = i.Choice{Text: v}
	}
	return vsm
}

func (FancyTerminal) Ask(params Prompt) (reply int, err error) {
	var resp int64

	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
					Msg: params.Question,
					Choices: i.Choices{
						Alternatives: mapToChoice(params.Choices),
					},
				},
				Action: func(c i.Context) interface{} {
					resp, _ = c.Ans().Int()
					return nil
				},
			},
		},
	})
	reply = int(resp)
	return
}

func (FancyTerminal) Inform(msg string) {
	fmt.Println(msg)
}

func (FancyTerminal) AskPassword(msg string) ([]byte, error) {
	fmt.Println(msg)
	return gopass.GetPasswd()
}

func (AskPass) Ask(params Prompt) (reply int, err error) {
	reply = -1
	var convErr error

	for convErr != nil || reply <= 0 || reply > len(params.Choices) { // 1 indexed
		cmd := exec.Command("ssh-askpass", formatPrompt(params))
		out, err := cmd.Output()
		if err != nil {
			return reply, err
		}
		sReply := strings.TrimSpace(string(out))
		reply, convErr = strconv.Atoi(sReply)
	}

	return
}

func (AskPass) Inform(msg string) {
	log.Printf(msg)
}

func (AskPass) AskPassword(msg string) ([]byte, error) {
	cmd := exec.Command("ssh-askpass", msg)
	out, err := cmd.Output()
	if err != nil {
		return out, err
	}
	return []byte(strings.TrimSpace(string(out))), nil
}
