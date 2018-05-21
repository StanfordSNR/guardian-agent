package main 

import(
    "os/exec"
    "os"
    "fmt"
    "strings"
    "os/user"
    "io/ioutil"
    "syscall"
    "bufio"
    "io"
)

const tokenLib = "/usr/local/lib/libykcs11_YUBICO.dylib"
const authKeyCert = "~/.ssh/auth-key-cert.pub"
const caPubKey = "/etc/ssh/ssh-ca-key.pub"
const authPubKey = "~/.ssh/auth-key.pub"

func main() {
    user, host, parseErr := parseArgs()
    if parseErr != nil {
        fmt.Printf("Error parsing arguments: %s\n", parseErr)
        return
    }
    generateErr := generateCert(user, host)
    if generateErr != nil {
        fmt.Println("Error generating certificate: %s\n", generateErr)
        return
    }
    stdinPipe, sshInputPipe := pipeSetup()
    startAuthLoop(user, host, stdinPipe, sshInputPipe)
}

// Return user, host, error
func parseArgs() (string, string, error) {
    args := os.Args[1:]
    if len(args) == 0 {
        return "", "", fmt.Errorf("Missing user@hostname")
    }
    destSlice := strings.Split(args[0], "@")
    if len(destSlice) == 1 {
        // Only have hostname. 
        userObj, err := user.Current()
        if err != nil {
            return "", "", fmt.Errorf("Cannot correctly identify current user: %s", err)
        }
        return userObj.Username, destSlice[0], nil
    }
    return destSlice[0], destSlice[1], nil
}

// Generate certificate from HW token.
func generateCert(username string, hostname string) error {
    if _, err := os.Stat(authKeyCert); os.IsNotExist(err) {
        fmt.Println("generating cert...")
        userObj, err := user.Current()
        fmt.Println("user name: ", userObj.Username)
        if err != nil {
            return fmt.Errorf("Cannot correctly identify current user: %s", err)
        }
        cmd := exec.Command("ssh-keygen", "-D", tokenLib, "-s", caPubKey, "-I", username, "-n", userObj.Username, authPubKey)
        cmd.Env = append(os.Environ())
        cmd.Stdin = os.Stdin
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr 
        cmd.Run()
    }
    return nil
}

func pipeSetup() (string, string) {
    tmpFile1, _ := ioutil.TempFile("/tmp", "user-input")
    name1 := tmpFile1.Name()
    os.Remove(tmpFile1.Name())
    syscall.Mkfifo(name1, 0666)
    go readStdinIntoPipe(name1)

    tmpFile2, _ := ioutil.TempFile("/tmp", "ssh-input")
    name2 := tmpFile2.Name()
    os.Remove(tmpFile2.Name())
    syscall.Mkfifo(name2, 0666)

    return name1, name2

}

func readStdinIntoPipe(pipe string) {
    f, err := os.OpenFile(pipe, os.O_RDWR, 0644)
    if err != nil {
        fmt.Printf("Error opening pipe %s: %s", pipe, err)
    }
    stdinReader := bufio.NewReader(os.Stdin)
    for {
        b,_ := stdinReader.ReadByte()
        n, err := f.Write([]byte{b})
        if n != 1 || err != nil {
            fmt.Printf("Error reading from stdin into pipe: %s", err)
        }
    }
}

func writeSshInputIntoPipe(inPipe string, outPipe io.WriteCloser) {
    in, err := os.OpenFile(inPipe, os.O_RDWR, 0644)
    if err != nil {
        fmt.Printf("Error opening pipe %s: %s", inPipe, err)
    }
    buffer := make([]byte, 1)
    for {
        n, err := in.Read(buffer)
        if err != nil {
            fmt.Printf("Error reading from ssh input: %s", err)
        }
        if n != 1 {
            fmt.Printf("Read no bytes.")
        }
        bytesWritten, errWrite := outPipe.Write(buffer)
        if bytesWritten != n || errWrite != nil {
            fmt.Printf("Error reading from ssh input into pipe: %s", errWrite)
        }
    }
}

// Run ssh continuously authenticating.
func startAuthLoop(username string, hostname string, stdinPipe string, sshInputPipe string) {
    cmd := exec.Command("ssh", "-o", fmt.Sprintf("ProxyCommand bash -c \"source auth-loop.sh %s %s %s %s\"", username, hostname, stdinPipe, sshInputPipe), "-i", authKeyCert, "-tt", fmt.Sprintf("%s@%s", username, hostname))
    cmd.Env = append(os.Environ())
    stdin, err := cmd.StdinPipe()
    if err != nil {
        fmt.Printf("Can't get stdin pipe")
    }
    go writeSshInputIntoPipe(sshInputPipe, stdin)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Start()
    cmd.Wait()
}
