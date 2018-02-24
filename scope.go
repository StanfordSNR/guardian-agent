package guardianagent

type Scope struct {
	ClientName      string `json:"ClientName"`
	ClientHostname  string `json:"ClientHostname"`
	ClientPort      uint32 `json:"ClientPort"`
	ServiceUsername string `json:"ServiceUsername"`
	ServiceHostname string `json:"ServiceHostname"`
}
