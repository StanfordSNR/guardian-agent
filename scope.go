package guardianagent

type Scope struct {
	ClientUsername  string `json:"ClientUsername"`
	ClientHostname  string `json:"ClientHostname"`
	ClientPort      uint32 `json:"ClientPort"`
	ServiceUsername string `json:"ServiceUsername"`
	ServiceHostname string `json:"ServiceHostname"`
}
