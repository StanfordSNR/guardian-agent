package main

import(
    "os"
    "os/exec"
    "fmt"
    "time"
    "bytes"
    "strings"
)

const authKeyCert = "~/.ssh/auth-key-cert.pub"
const tokenLib = "/usr/local/lib/libykcs11_YUBICO.dylib"

func main() {
    args := os.Args[1:]
    username := args[0]
    hostname := args[1]
    socket := args[2]
    for {
        start := time.Now()
        timedAuth(username, hostname, socket)
        elapsed := time.Now().Sub(start)
        noAuth := elapsed < 9 * time.Second
        keyPresent := isYubikeyPresent()
        if !keyPresent {
            time.Sleep(time.Second)
        } else if noAuth && keyPresent {
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

func enterPasscode() {
    eval := exec.Command("eval", "`ssh-agent -s`")
    eval.Env = append(os.Environ())
    eval.Run()
    add := exec.Command("ssh-add", fmt.Sprintf("-s %s", tokenLib))
    add.Env = append(os.Environ())
    add.Run()
}
