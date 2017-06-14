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

type PromptUserFunc func(prompt Prompt) (string, error)

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
	buf.WriteString("\n? Answer: ")
	formattedPrompt = buf.String()
	return
}

func TerminalPrompt(params Prompt) (reply string, err error) {
	reply = "-1"
	iReply, convErr := strconv.Atoi(reply)

	for convErr != nil || iReply <= 0 || iReply > len(params.Choices) {
		fmt.Print(formatPrompt(params))
		reader := bufio.NewReader(os.Stdin)
		reply, err = reader.ReadString('\n')
		iReply, convErr = strconv.Atoi(strings.TrimSpace(reply))
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

func FancyTerminalPrompt(params Prompt) (reply string, err error) {
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
	reply = strconv.Itoa(int(resp))
	return
}

func AskPassPrompt(params Prompt) (reply string, err error) {
	reply = "-1"
	iReply, convErr := strconv.Atoi(reply)

	for convErr != nil || iReply <= 0 || iReply > len(params.Choices) { // 1 indexed
		cmd := exec.Command("ssh-askpass", formatPrompt(params))
		out, err := cmd.Output()
		if err != nil {
			break
		}
		reply = strings.TrimSpace(string(out))
		iReply, convErr = strconv.Atoi(reply)
	}

	return reply, err
}
