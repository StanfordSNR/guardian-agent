# Guardo Readme

1. `guardo-agent` -- the privileged daemon (that will actually be doing the privileged syscalls). Should be run as root (e.g., using `sudo`). Example:
```
 sudo $GOPATH/bin/guardo-agent
```

2. `sga-guard-bin` -- the agent. Should be setuid to root (to prevent unprivileged attacks on the process). Use `--prompt=[TERMINAL|DISPLAY|CONSOLE]` to choose the UI mode: terminal prompts, ssh-askpass GUI, and virtual console. Example: 
```
sudo chown root:root $GOPATH/bin/sga-guard-bin 
sudo chmod +s $GOPATH/bin/sga-guard-bin 
$GOPATH/bin/sga-guard-bin
```

3. `libhooks.so` -- the interception library. Should be LD_PRELOADED to the unprivileged procses. Example: 
```
LD_PRELOAD=$(BUILDDIR)/libaba/.libs/libhooks.so <executable> <args>
```