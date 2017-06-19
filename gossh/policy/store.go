package policy

import (
	"encoding/json"
	"log"
	"os"
	"sync"
)

type Store struct {
	mutex sync.RWMutex
	rules map[Scope]allowedCommands
	path  string
}

type allowedCommands struct {
	allCommands bool     `json:"AllCommands"`
	commands    []string `json:"Commands"`
}

type storageEntry struct {
	PolicyScope Scope           `json:"Scope"`
	PolicyRule  allowedCommands `json:"AllowedCommands"`
}

func NewStore(configPath string) (err error, store Store) {
	store = Store{
		path: configPath,
	}
	err = store.load()

	return err, store
}

func (store *Store) load() (err error) {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	file, err := os.OpenFile(store.path, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	dec := json.NewDecoder(file)
	if dec.More() {
		if err = dec.Decode(&store.rules); err != nil {
			log.Printf("err is %s", err)
			return err
		}
	}
	return nil
}

func (store *Store) Save() (err error) {
	file, err := os.OpenFile(store.path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := enc.Encode(&store); err != nil {
		return err
	}
	return nil
}

func (store *Store) MarshalJSON() ([]byte, error) {
	ps := []storageEntry{}
	for k, v := range store.rules {
		ps = append(ps, storageEntry{PolicyScope: k, PolicyRule: v})
	}
	val, err := json.Marshal(ps)

	if err != nil {
		return nil, err
	}
	return val, nil
}

func (store Store) UnmarshalJSON(b []byte) error {
	tmpStore := []storageEntry{}
	err := json.Unmarshal(b, &tmpStore)

	if err != nil {
		return err
	}
	for _, v := range tmpStore {
		store.rules[v.PolicyScope] = v.PolicyRule
	}

	return nil
}

func (store Store) AllowAll(scope Scope) (err error) {
	store.mutex.RLock()
	cmds, ok := store.rules[scope]
	if !ok {
		cmds = allowedCommands{
			allCommands: false,
			commands:    make([]string, 0)}
	}
	cmds.allCommands = true
	store.mutex.RUnlock()
	return store.Save()
}

func (store Store) AllowCommand(scope Scope, cmd string) (err error) {
	store.mutex.RLock()
	allowed, ok := store.rules[scope]
	if !ok {
		allowed = allowedCommands{
			allCommands: false,
			commands:    make([]string, 0)}
	}
	for _, command := range allowed.commands {
		if cmd == command {
			return
		}
	}
	allowed.commands = append(allowed.commands, cmd)
	store.mutex.RUnlock()
	return store.Save()
}

func (store Store) IsAllowed(scope Scope, cmd string) bool {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	allowed, ok := store.rules[scope]
	if !ok {
		return false
	}

	if allowed.allCommands {
		return true
	}
	for _, storedCommand := range allowed.commands {
		if cmd == storedCommand {
			return true
		}
	}
	return false
}

func (store Store) AreAllAllowed(scope Scope) bool {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	allowed, ok := store.rules[scope]
	if !ok {
		return false
	}

	return allowed.allCommands
}
