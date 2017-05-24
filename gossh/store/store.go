package store

import (
    "encoding/json"
    "os"
)

// TODO: figure out format
// TODO: work out synchronization for multiple agents per client?
const configLocation = "~/.ssh/agent_policies"

type PolicyKey struct {
    cUser   string // this is the connecting user (making request)
    cClient string // this is the connecting client/machine (making request)
}

type RequestedPerm struct {
// the agent creds the client wants to user
    AUser   string
    AServer string
}

type PolicyScope map[RequestedPerm]PolicyRule
    
type PolicyRule struct {
    AllCommands     bool
    Commands        []string
}

type storageUnit struct {
    key     PolicyKey
    scope   PolicyScope
}

// type policyStore map[PolicyKey]PolicyScope

func load() (err error, store map[PolicyKey]PolicyScope) {

    store = make(map[PolicyKey]PolicyScope)
    file, err := os.Open(configLocation)
    if os.IsNotExist(err) {
        // initialize new one
        return nil, store
    } else {
        return
    }
    dec := json.NewDecoder(file)

    var su storageUnit
    for err := dec.Decode(&su); err == nil; err = dec.Decode(&su) {
        store[su.key] = su.scope
    }
    file.Close()

    return nil, store
}

func ScopedStore(cUser string, cClient string) (err error, scope PolicyScope) {
    err, store := load()
    if err != nil {
        return err, nil
    }
    scope = store[PolicyKey{cUser: cUser, cClient: cClient}]
    if scope == nil {
        scope = make(PolicyScope)
    }
    return nil, scope
}

func Store(cUser string, cClient string, scopedStore PolicyScope) (err error) {

    // read first to only edit client's part.
    err, store := load()
    if err != nil {
        return
    }

    // double IO with load... refactor?
    file, err := os.Open(configLocation)
    if err != nil {
        if os.IsNotExist(err) {
            file, err := os.Create(configLocation)
            if err != nil {
                file.Close()
                return err
            }
        } else {
            return err
        }
    }

    store[PolicyKey {cUser: cUser, cClient: cClient}] = scopedStore

    enc := json.NewEncoder(file)
    for k, v := range store {    
        err = enc.Encode(storageUnit{key: k, scope: v})        
        if err != nil {
            return err
        }
    }
    file.Close()

    return nil
}



