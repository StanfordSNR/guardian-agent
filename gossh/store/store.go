package store

import (
    "encoding/json"
    "os"
    "os/user"
    "log"
    "fmt"
)

// TODO: figure out format
// TODO: work out synchronization for multiple agents per client?
func configLocation() (error, string) {
    usr, err := user.Current()
    if err != nil {
        return err, ""
    }
    return nil, fmt.Sprintf("%s/.ssh/agent_policies", usr.HomeDir)
}

type PolicyKey struct {
    cUser   string // this is the connecting user (making request)
    cClient string // this is the connecting client/machine (making request)
}

type RequestedPerm struct {
// the agent creds the client wants to use
    AUser   string
    AServer string
}

type PolicyScope map[RequestedPerm]PolicyRule

type PolicyRule struct {
    AllCommands     bool
    Commands        []string
}

type ScopedStore struct {
    Key     PolicyKey
    Scope   PolicyScope
}

// type policyStore map[PolicyKey]PolicyScope

func load() (err error, store map[PolicyKey]PolicyScope) {

    store = make(map[PolicyKey]PolicyScope)
    err, configLocation := configLocation()
    if err != nil {
        return
    }

    file, err := os.Open(configLocation)
    if os.IsNotExist(err) {
        // initialize new one
        return nil, store
    } else {
        return
    }
    dec := json.NewDecoder(file)

    var scoS ScopedStore
    for err := dec.Decode(&scoS); err == nil; err = dec.Decode(&scoS) {
        store[scoS.Key] = scoS.Scope
    }
    file.Close()

    return nil, store
}

func FetchScopedStore(cUser string, cClient string) (err error, scopedStore ScopedStore) {
    key := PolicyKey{cUser: cUser, cClient: cClient}
    err, store := load()
    log.Printf("err %s\nstore %s", err, store)
    if err != nil {
        scope := make(PolicyScope)
        return err, ScopedStore{Key: key, Scope: scope}
    }
    scope := store[key]
    if scope == nil {
        scope = make(PolicyScope)
    }
    return nil, ScopedStore{Key: key, Scope: scope}
}

func (scoS *ScopedStore) Save() error {
    // read first to only edit client's part.
    err, store := load()
    if err != nil {
        return err
    }

    err, configLocation := configLocation()
    if err != nil {
        return err
    }

    var file *os.File
    if _, err = os.Stat(configLocation); err == nil {
        file, err = os.Open(configLocation)
        if err != nil {
            return err
        } 
    } else {
        file, err = os.Create(configLocation) 
        if err != nil {
            return err
        }
    }

    store[scoS.Key] = scoS.Scope

    enc := json.NewEncoder(file)
    for k, v := range store {    
        err = enc.Encode(ScopedStore{Key: k, Scope: v})        
        if err != nil {
            return err
        }
    }
    file.Close()

    return nil
}



