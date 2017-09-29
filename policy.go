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
		policy.UI.Inform(fmt.Sprintf("Request by %s@%s:%d to run '%s' on %s@%s auto approved by policy",
			scope.ClientUsername, scope.ClientHostname,
			scope.ClientPort, cmd, scope.ServiceUsername,
			scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Allow %s@%s:%d to run '%s' on %s@%s?",
		scope.ClientUsername, scope.ClientHostname,
		scope.ClientPort, cmd, scope.ServiceUsername,
		scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices: []string{
			"Disallow", "Allow once", "Allow forever",
			fmt.Sprintf("Allow %s@%s:%d to run any command on %s@%s forever",
				scope.ClientUsername, scope.ClientHostname,
				scope.ClientPort, scope.ServiceUsername,
				scope.ServiceHostname),
		},
	}
	resp, err := policy.UI.Ask(prompt)
	if err != nil {
		return fmt.Errorf("Failed to get user approval: %s", err)
	}

	switch resp {
	case 1:
		err = errors.New("User rejected client request")
	case 2:
		err = nil
	case 3:
		err = policy.Store.AllowCommand(scope, cmd)
	case 4:
		err = policy.Store.AllowAll(scope)
	}

	return err
}

func (policy *Policy) RequestApprovalForAllCommands(scope Scope) error {
	if policy.Store.AreAllAllowed(scope) {
		policy.UI.Inform(fmt.Sprintf("Request by %s@%s:%d to run any command on %s@%s auto approved by policy",
			scope.ClientUsername, scope.ClientHostname,
			scope.ClientPort, scope.ServiceUsername, scope.ServiceHostname))
		return nil
	}
	question := fmt.Sprintf("Can't enforce permission for a single command. Allow %s@%s:%d to run any command on %s@%s?",
		scope.ClientUsername, scope.ClientHostname,
		scope.ClientPort, scope.ServiceUsername,
		scope.ServiceHostname)

	prompt := Prompt{
		Question: question,
		Choices:  []string{"Disallow", "Allow for session", "Allow forever"},
	}
	resp, err := policy.UI.Ask(prompt)

	switch resp {
	case 1:
		err = errors.New("Policy rejected approval escalation")
	case 2:
		err = nil
	case 3:
		err = policy.Store.AllowAll(scope)
	}

	return err
}