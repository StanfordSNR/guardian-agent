package guardianagent

import (
	"errors"
	"fmt"
)

type Policy struct {
	Store *Store
	UI    UI
}

func (policy *Policy) RequestApproval(scope Scope, cmd string) error {
	if policy.Store.IsAllowed(scope, cmd) {
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s AUTO-APPROVED by policy",
			scope.Client, cmd, scope.ServiceUsername,
			scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Allow %s to run '%s' on %s@%s?",
		scope.Client, cmd, scope.ServiceUsername, scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices: []string{
			"Disallow", "Allow once", "Allow forever",
			fmt.Sprintf("Allow %s to run any command on %s@%s forever",
				scope.Client, scope.ServiceUsername, scope.ServiceHostname),
		},
	}
	resp, err := policy.UI.Ask(prompt)
	if err != nil {
		return fmt.Errorf("Failed to get user approval: %s", err)
	}

	switch resp {
	case 2:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s APPROVED by user",
			scope.Client, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = nil
	case 3:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s PERMANENTLY APPROVED by user",
			scope.Client, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowCommand(scope, cmd)
	case 4:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s PERMANENTLY APPROVED by user",
			scope.Client, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowAll(scope)
	default:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run '%s' on %s@%s DENIED by user",
			scope.Client, cmd, scope.ServiceUsername, scope.ServiceHostname))
		err = errors.New("User rejected client request")
	}

	return err
}

func (policy *Policy) RequestApprovalForAllCommands(scope Scope) error {
	if policy.Store.AreAllAllowed(scope) {
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s AUTO-APPROVED by policy",
			scope.Client, scope.ServiceUsername, scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Can't enforce permission for a single command. Allow %s to run ANY COMMAND on %s@%s?",
		scope.Client, scope.ServiceUsername, scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices:  []string{"Disallow", "Allow once", "Allow forever"},
	}
	resp, err := policy.UI.Ask(prompt)

	switch resp {
	case 2:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s APPROVED by user",
			scope.Client, scope.ServiceUsername, scope.ServiceHostname))
		err = nil
	case 3:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s PERMANENTLY APPROVED by user",
			scope.Client, scope.ServiceUsername, scope.ServiceHostname))
		err = policy.Store.AllowAll(scope)
	default:
		policy.UI.Inform(fmt.Sprintf("Request by %s to run ANY COMMAND on %s@%s DENIED by user",
			scope.Client, scope.ServiceUsername, scope.ServiceHostname))
		err = errors.New("User rejected approval escalation")
	}

	return err
}
