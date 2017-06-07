package policy

import (
    "encoding/json"
    "os"
    "os/user"
    "fmt"
    // "bytes"
    "io/ioutil"
    // "sync"
    "log"
)

func configLocation() (error, string) {
    usr, err := user.Current()
    if err != nil {
        return err, ""
    }
    return nil, fmt.Sprintf("%s/.ssh/agent_policies", usr.HomeDir)
}

type Scope struct {
    ClientUsername  string `json:"ClientUsername"`
    ClientHostname  string `json:"ClientHostname"`
    ClientPort      uint32 `json:"ClientPort"`
    ServiceUsername string `json:"ServiceUsername"`
    ServiceHostname string `json:"ServiceHostname"`
}

type Rule struct {
    AllCommands     bool     `json:"AllCommands"`
    Commands        []string `json:"Commands"`
}

type Store map[Scope]Rule

type storageEntry struct {
    PolicyScope Scope `json:"Scope"`
    PolicyRule  Rule  `json:"Rule"`
}
type persistentStore []storageEntry

func (rule Rule) IsApproved(reqCommand string) bool {
    if rule.AllCommands {
        return true
    }
    for _, storedCommand := range rule.Commands {
        if reqCommand == storedCommand {
            return true
        }
    }
    return false
}

func (store Store) GetRule(scope Scope) Rule {
    
    storedRule, ok := store[scope]
    if ok {
        return storedRule
    } else {
        return Rule{ AllCommands: false, Commands: make([]string, 0) }
    }
}

func (store Store) SetAllAllowedInScope(sc Scope) (err error) {
    rule := store.GetRule(sc)
    rule.AllCommands = true
    store[sc] = rule
    err = store.save()

    return
}

func (store Store) SetCommandAllowedInScope(sc Scope, newCommand string) (err error) {
    rule := store.GetRule(sc)
    for _, command := range rule.Commands {
        if command == newCommand {
            return
        }
    }
    rule.Commands = append(rule.Commands, newCommand)
    err = store.save()

    return
}

func LoadStore() (err error, store Store) {

    err = nil
    store = make(Store)
    err = store.load()
    
    return err, store
}

func (store *Store) load() (err error) {
    err, configLocation := configLocation()
    if err != nil {
        return
    }

    data, err := ioutil.ReadFile(configLocation)

    file, err := os.Open(configLocation)
    if err != nil {
        log.Panic(err)
    }

    dec := json.NewDecoder(file)

    if err = dec.Decode(&store); err != nil {
        fmt.Println("err is %s", err)
        return err
    }
    return nil
}

func (store *Store) save() (err error) {

    err, configLocation := configLocation()
    if err != nil {
        return err
    }

    var file *os.File
    file, err = os.OpenFile(configLocation, os.O_WRONLY|os.O_CREATE, 0600)
    if err != nil {
        return err
    } 

    enc := json.NewEncoder(file)
    if err := enc.Encode(&store); err != nil {
        return err
    }
    return nil
}

func (store *Store) MarshalJSON() ([]byte, error) {
    fmt.Println("weird bug 1 %s", store)
    ps := make(persistentStore, 1)
    for k, v := range *store {
        ps = append(ps, storageEntry{PolicyScope: k, PolicyRule: v})
    }
    val, err := json.Marshal(ps)

    if err != nil {
        return nil, err
    }
    fmt.Println("Weird bug2 %s", string(val))
 
    return val, nil
}

func (store Store) UnmarshalJSON(b []byte) error {
    tmpStore := make(persistentStore, 1)
    err := json.Unmarshal(b, &tmpStore)

    if err != nil {
        return err
    }
    for _, v := range tmpStore {
        store[v.PolicyScope] = v.PolicyRule
    }

    return nil
}