package common

import (
	"bufio"
	"bytes"
	"fmt"
	i "github.com/sternhenri/interact"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type PromptUserFunc func(prompt Prompt) (int, error)

type Prompt struct {
	Question string
	Choices  []string
}

func formatPrompt(params Prompt) (formattedPrompt string) {
	var buf bytes.Buffer
	buf.WriteString(params.Question)
	for i, v := range params.Choices {
		buf.WriteString(fmt.Sprintf("\n\t%d) %s", i+1, v))
	}
	buf.WriteString("\n\nAnswer (enter a number): ")
	formattedPrompt = buf.String()
	return
}

func TerminalPrompt(params Prompt) (reply int, err error) {
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

func MapToChoice(vs []string) []i.Choice {
	vsm := make([]i.Choice, len(vs))
	for j, v := range vs {
		vsm[j] = i.Choice{Text: v}
	}
	return vsm
}

func FancyTerminalPrompt(params Prompt) (reply int, err error) {
	var resp int64

	i.Run(&i.Interact{
		Questions: []*i.Question{
			{
				Quest: i.Quest{
					Msg: params.Question,
					Choices: i.Choices{
						Alternatives: MapToChoice(params.Choices),
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

func AskPassPrompt(params Prompt) (reply int, err error) {
	reply = -1
    var convErr error

	for convErr != nil || reply <= 0 || reply > len(params.Choices) { // 1 indexed
		cmd := exec.Command("ssh-askpass", formatPrompt(params))
		out, err := cmd.Output()
		if err != nil {
			break
		}
		sReply := strings.TrimSpace(string(out))
		reply, convErr = strconv.Atoi(sReply)
	}

	return
}
