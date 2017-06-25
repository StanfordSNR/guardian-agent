package policy

import (
	"encoding/json"
	"os"
	"sync"
)

type Store struct {
	mutex sync.RWMutex
	rules map[Scope]AllowedCommands
	path  string
}

type AllowedCommands struct {
	AllCommands bool     `json:"AllCommands"`
	Commands    []string `json:"Commands"`
}

type storageEntry struct {
	PolicyScope Scope           `json:"Scope"`
	PolicyRule  AllowedCommands `json:"AllowedCommands"`
}

func NewStore(configPath string) (store *Store, err error) {
	store = &Store{
		path:  configPath,
		rules: make(map[Scope]AllowedCommands),
	}
	err = store.load()

	return store, err
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
		if err = dec.Decode(&store); err != nil {
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
	if err := enc.Encode(store); err != nil {
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

func (store *Store) UnmarshalJSON(b []byte) error {
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

func (store *Store) AllowAll(scope Scope) (err error) {
	store.mutex.RLock()
	allowed, ok := store.rules[scope]
	if !ok {
		allowed = AllowedCommands{
			AllCommands: false,
			Commands:    []string{}}
	}
	allowed.AllCommands = true
	store.rules[scope] = allowed
	store.mutex.RUnlock()

	return store.Save()
}

func (store *Store) AllowCommand(scope Scope, cmd string) (err error) {
	store.mutex.Lock()
	allowed, ok := store.rules[scope]
	if !ok {
		allowed = AllowedCommands{
			AllCommands: false,
			Commands:    []string{}}
	}
	for _, command := range allowed.Commands {
		if cmd == command {
			return
		}
	}
	allowed.Commands = append(allowed.Commands, cmd)
	store.rules[scope] = allowed
	store.mutex.Unlock()

	return store.Save()
}

func (store *Store) IsAllowed(scope Scope, cmd string) bool {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	allowed, ok := store.rules[scope]
	if !ok {
		return false
	}

	if allowed.AllCommands {
		return true
	}
	for _, storedCommand := range allowed.Commands {
		if cmd == storedCommand {
			return true
		}
	}
	return false
}

func (store *Store) AreAllAllowed(scope Scope) bool {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	allowed, ok := store.rules[scope]
	if !ok {
		return false
	}

	return allowed.AllCommands
}
