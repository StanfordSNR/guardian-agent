package store

import (
    "encoding/json"
    "os"
    "os/user"
    "log"
    "fmt"
    "bytes"
    "strings"
    "io/ioutil"
    "github.com/bitly/go-simplejson"
)

// TODO: work out synchronization for multiple agents per client?
func configLocation() (error, string) {
    usr, err := user.Current()
    if err != nil {
        return err, ""
    }
    return nil, fmt.Sprintf("%s/.ssh/agent_policies", usr.HomeDir)
}

type PolicyKey struct {
    CUser   string `json:"CUser"`// this is the connecting user (making request)
    CClient string `json:"CClient"`// this is the connecting client/machine (making request)
}

type RequestedPerm struct {
// the agent creds the client wants to use
    AUser   string `json:"AUser"`
    AServer string `json:"AServer"`
}

type PolicyRule struct {
    AllCommands     bool        `json:"AllCommands"`
    Commands        []string    `json:"Commands"`
}

type PolicyScope map[RequestedPerm]PolicyRule

type ScopedStore struct {
    PolicyKey     PolicyKey     `json:"PolicyKey"`
    PolicyScope   PolicyScope   `json:"PolicyScope"`
}

// type policyStore map[PolicyKey]PolicyScope

func load() (err error, store map[PolicyKey]PolicyScope) {

    store = make(map[PolicyKey]PolicyScope)
    err, configLocation := configLocation()
    if err != nil {
        return
    }

    data, err := ioutil.ReadFile(configLocation)
    if err != nil {
        // silent fail
        return nil, store
    }

    val, err := simplejson.NewJson(data)

    // let's build it back up
    policies, err := val.Array()
    if err != nil {
        return
    }

    store = parseStore(store, policies)

    return nil, store
}

func parseStore(inStore map[PolicyKey]PolicyScope, policies []interface{}) (store map[PolicyKey]PolicyScope) {
        for _, policy := range policies {
        policy := policy.(map[string]interface{})

        var pk PolicyKey
        ps := make(PolicyScope)
        for k, v := range policy {

            if k == "PolicyKey" {
                var cU, cC string
                v := v.(map[string]interface{})
                for kv, vv := range v {
                    if kv == "CUser" {
                        cU = vv.(string)
                    } else if kv == "CClient" {
                        cC = vv.(string)
                    }
                }
                pk = PolicyKey{CUser: cU, CClient: cC}
            } else if k == "PolicyScope" {
                for _, scope := range v.([]interface{}) {
                    scope := scope.(map[string]interface{})
                    aC := false
                    var cmds []string
                    var aU, aS string
                    var pr PolicyRule
                    var rp RequestedPerm
                    for sk, sv := range scope {
                        sv := sv.(map[string]interface{})
                        if sk == "PolicyRule" {
                            for svk, svv := range sv {
                                if svk == "AllCommands" {
                                    aC = svv.(bool) 
                                } else if svk == "Commands" {
                                    svv := svv.([]interface {})
                                    for _, cmd := range svv {
                                        cmds = append(cmds, cmd.(string))
                                    }
                                }
                            }
                        } else if sk == "RequestedPerm" {
                            for svk, svv := range sv {
                                if svk == "AUser" {
                                    aU = svv.(string)
                                } else if svk == "AServer" {
                                    aS = svv.(string)
                                }
                            }
                        }
                    }
                    rp = RequestedPerm{AUser: aU, AServer: aS}
                    pr = PolicyRule{AllCommands: aC, Commands: cmds}
                    ps[rp] = pr
                }
            }
            inStore[pk] = ps
        }
    }
    return inStore
}

func FetchScopedStore(cUser string, cClient string) (err error, scopedStore ScopedStore) {
    key := PolicyKey{CUser: cUser, CClient: cClient}
    err, store := load()
    log.Printf("err %s\nstore %s", err, store)
    if err != nil {
        scope := make(PolicyScope)
        return err, ScopedStore{PolicyKey: key, PolicyScope: scope}
    }
    scope := store[key]
    if scope == nil {
        scope = make(PolicyScope)
    }
    return nil, ScopedStore{PolicyKey: key, PolicyScope: scope}
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
        file, err = os.OpenFile(configLocation, os.O_RDWR|os.O_CREATE, 0700)
        if err != nil {
            return err
        } 
    } else {
        file, err = os.Create(configLocation) 
        if err != nil {
            return err
        }
    }

    store[scoS.PolicyKey] = scoS.PolicyScope

/* Goal is: 
[{
    "PolicyKey": {
        "CUser": "placeholderUser",
        "CClient": "placeholderClient"
    },
    "PolicyScope": [{
        "RequestedPerm": {
            "AUser": "Henri",
            "AServer": "127.0.0.1:22"
        },
        "PolicyRule": {
            "AllCommands": true,
            "Commands": []
        }
    }]
}]
*/
    enc := json.NewEncoder(file)

    // FUCK golang json library
    var storeBuf bytes.Buffer
    storeMax := len(store)
    storeCount := 0
    storeBuf.Write([]byte("["))
    for key, scope := range store {
        jsonKey := []byte(fmt.Sprintf(`{"PolicyKey": {"CUser": "%s", "CClient": "%s"}`, key.CUser, key.CClient))

        var scopeBuf bytes.Buffer
        scopeMax := len(scope)
        scopeCount := 0
        scopeBuf.Write([]byte(`"PolicyScope": [`))
        for perm, rule := range scope {
            jsonPerm := []byte(fmt.Sprintf(`{"RequestedPerm": {"AUser": "%s", "AServer": "%s"}`, perm.AUser, perm.AServer))

            var jsonCommands string
            if len(rule.Commands) > 0 {
                jsonCommands = fmt.Sprintf("%s", strings.Join(rule.Commands, `", "`))
            } else {
                jsonCommands = ""
            }
            jsonRule := []byte(fmt.Sprintf(`"PolicyRule": {"AllCommands": %t, "Commands":[%s]}`, rule.AllCommands, jsonCommands))

            jsonScope := []byte(fmt.Sprintf(`%s, %s`, jsonPerm, jsonRule))
            scopeBuf.Write(jsonScope)
            scopeCount ++
            if scopeCount < scopeMax {
                scopeBuf.Write([]byte("}, "))
            }
        }
        scopeBuf.Write([]byte("}]"))
        storeBuf.Write([]byte(fmt.Sprintf("%s, %s", jsonKey, scopeBuf.String())))
        storeCount ++
        if storeCount < storeMax {
            storeBuf.Write([]byte("}, "))
        }
    }
    storeBuf.Write([]byte("}]"))
    
    // (dimakogan) - first one will hash, second more efficient, can also prettify with simplejson - delete your file if you change
    // 1
    // err = enc.Encode(storeBuf.Bytes())
    // 2
    err = enc.Encode(json.RawMessage(storeBuf.String()))

    if err != nil {
        return err
    }

    file.Close()
    return nil
}



