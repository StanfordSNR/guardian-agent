package main

import(
    "os"
    "os/exec"
    "fmt"
    "time"
    "bytes"
    "strings"
    "sync"
)

const authKeyCert = "~/.ssh/auth-key-cert.pub"
const tokenLib = "/usr/local/lib/libykcs11_YUBICO.dylib"

var auth = false
var authLock sync.RWMutex

func main() {
    args := os.Args[1:]
    username := args[0]
    hostname := args[1]
    socket := args[2]
    stdinPipe := args[3]
    sshInputPipe := args[4]
    startAuthCh := make(chan bool, 1)
    go filterInput(stdinPipe, sshInputPipe)
    go checkAuthStatus(&startAuthCh)

    for {
        timedAuth(username, hostname, socket)
        startAuthCh <- true
        authLock.RLock()
        authCopy := auth
        authLock.RUnlock()
        keyPresent := isYubikeyPresent()
        if !keyPresent {
            time.Sleep(time.Second)
        } else if !authCopy && keyPresent {
            // Just plugged in key.
           return
        }
    }
}

func timedAuth(username string, hostname string, socket string) {
    setup := exec.Command("ssh", "-q", "-i", authKeyCert, "-o", "BatchMode=yes", fmt.Sprintf("%s@%s", username, hostname), fmt.Sprintf("%s", generateKillConnCmd(socket)))
    setup.Env = append(os.Environ())
    setup.Start()
    conn := exec.Command("ssh", "-q", "-i", authKeyCert, "-o", "BatchMode=yes", fmt.Sprintf("%s@%s", username, hostname), fmt.Sprintf("nc -U %s", socket))
    conn.Stderr = os.Stderr
    conn.Stdin = os.Stdin
    conn.Stdout = os.Stdout
    conn.Run()
}

func generateKillConnCmd(socket string) string {
    return fmt.Sprintf("sleep 10s; conn=$(ps aux | grep \"nc -U %s\" | grep -v grep | awk '{print $2}'); kill $conn &> /dev/null; wait $conn &> /dev/null", socket);
}

func isYubikeyPresent() bool {
    checkKey := exec.Command("lsusb", " &> /dev/null")
    var outb bytes.Buffer
    checkKey.Stdout = &outb
    checkKey.Run()
    return strings.Contains(outb.String(), "Yubikey")
}

func checkAuthStatus(startAuthCh *chan bool) {
    start := time.Now()
    for {
        select {
        case <- time.After(100*time.Millisecond):
            if (time.Since(start).Seconds() > 2) {
                authLock.Lock()
                auth = true
                authLock.Unlock()
            }

        case <- *startAuthCh:
            if time.Since(start).Seconds() < 2 {
                authLock.Lock()
                auth = false
                authLock.Unlock()
            }
            start = time.Now()
        }
   }
}

func filterInput(stdinPipe string, sshInputPipe string) {
    in,_  := os.OpenFile(stdinPipe, os.O_RDWR, 0644)
    out,_ := os.OpenFile(sshInputPipe, os.O_RDWR, 0644)
    buffer := make([]byte, 1)
    for {
        in.Read(buffer)
        authLock.RLock()
        authCopy := auth
        authLock.RUnlock()
        if authCopy {
            out.Write(buffer)
        }
    }
}
