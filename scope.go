package guardianagent

type Scope struct {
	Client          string `json:"Client"`
	ServiceUsername string `json:"ServiceUsername"`
	ServiceHostname string `json:"ServiceHostname"`
}
