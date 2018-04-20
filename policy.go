package guardianagent

import (
	"errors"
	"fmt"
)

type Policy struct {
	Store               *Store
	UI                  UI
	currentSmartOptions []SmartOption
}

func (policy *Policy) RequestCredentialApproval(scope Scope, req *CredentialRequest) error {
	syscallInfo := NewSyscallInfo(req.GetOp())
	desc := fmt.Sprintf("request by [%s] on %s to call:\n\t%s\non %s as root",
		req.GetOp().GetCaller().Cmdline,
		scope.ClientName, syscallInfo.Desc, req.GetChallenge().ServerHostname)

	for _, so := range policy.currentSmartOptions {
		isOk, approvalString := so.IsAllowed(scope, req.GetOp().Caller, syscallInfo)
		if isOk {
			policy.UI.Inform(desc + " " + approvalString)
			return nil
		}
	}

	question := "Allow " + desc + "?"
	prompt := Prompt{
		Question: question,
		Choices:  []string{"Disallow", "Allow once"},
	}
	approvalStrings := []string{desc + " DENIED by user", desc + " APPROVED by user"}

	smartOptions := GetSmartOptions(scope, req.GetOp().Caller, syscallInfo)
	for _, so := range smartOptions {
		promptString, approvalString := so.Prompt()
		prompt.Choices = append(prompt.Choices, promptString)
		approvalStrings = append(approvalStrings, approvalString)
	}
	resp, err := policy.UI.Ask(prompt)
	if err != nil {
		return fmt.Errorf("Failed to get user approval: %s", err)
	}
	// Turn to zero based
	resp -= 1
	if (resp <= 0) || (resp >= len(approvalStrings)) {
		return errors.New("User rejected client request")
	}
	policy.UI.Inform(approvalStrings[resp])
	if resp >= 2 {
		policy.currentSmartOptions = append(policy.currentSmartOptions, smartOptions[resp-2])
	}
	return nil
}

func (policy *Policy) RequestApproval(scope Scope, cmd string) error {
	if policy.Store.IsAllowed(scope, cmd) {
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s AUTO-APPROVED by policy",
			scope.ClientName, cmd, scope.ServiceUsername,
			scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Allow %s to run '%s' on %s@%s?",
		scope.ClientName, cmd, scope.ServiceUsername, scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices: []string{
			"Disallow", "Allow once", "Allow forever",
			fmt.Sprintf("Allow %s to run any command on %s@%s forever",
				scope.ClientName, scope.ServiceUsername, scope.ServiceHostname),
		},
	}
	resp, err := policy.UI.Ask(prompt)
	if err != nil {
		return fmt.Errorf("Failed to get user approval: %s", err)
	}

	switch resp {
	case 2:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s APPROVED by user",
			scope.ClientName, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = nil
	case 3:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s PERMANENTLY APPROVED by user",
			scope.ClientName, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowCommand(scope, cmd)
	case 4:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s PERMANENTLY APPROVED by user",
			scope.ClientName, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowAll(scope)
	default:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s DENIED by user",
			scope.ClientName, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = errors.New("User rejected client request")
	}

	return err
}

func (policy *Policy) RequestApprovalForAllCommands(scope Scope) error {
	if policy.Store.AreAllAllowed(scope) {
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s AUTO-APPROVED by policy",
			scope.ClientName, scope.ServiceUsername, scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Can't enforce permission for a single command. Allow %s to run ANY COMMAND on %s@%s?",
		scope.ClientName, scope.ServiceUsername, scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices:  []string{"Disallow", "Allow once", "Allow forever"},
	}
	resp, err := policy.UI.Ask(prompt)

	switch resp {
	case 2:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s APPROVED by user",
			scope.ClientName, scope.ServiceUsername, scope.ServiceHostname))
		err = nil
	case 3:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s PERMANENTLY APPROVED by user",
			scope.ClientName, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowAll(scope)
	default:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s DENIED by user",
			scope.ClientName, scope.ServiceUsername, scope.ServiceHostname))
		err = errors.New("User rejected approval escalation")
	}

	return err
}
