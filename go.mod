module github.com/StanfordSNR/guardian-agent

go 1.19

require (
	github.com/hashicorp/yamux v0.1.1
	github.com/howeyc/gopass v0.0.0-20210920133722-c8aef6fb66ef
	github.com/jessevdk/go-flags v1.5.0
	github.com/sternhenri/interact v0.0.0-20170607043113-dfeb9ef20304
	golang.org/x/crypto v0.11.0
	golang.org/x/sys v0.10.0
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
)

replace golang.org/x/crypto => github.com/StanfordSNR/crypto v0.0.0-20171223202347-4a3cd0184db6
