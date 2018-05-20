package main 

import(
    "os/exec"
    "os"
    "fmt"
    "strings"
    "os/user"
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
    //generateErr := generateCert(user, host)
    //if generateErr != nil {
    //    fmt.Println("Error generating certificate: %s\n", generateErr)
    //    return
    //}
    startAuthLoop(user, host)
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

// Run ssh continuously authenticating.
func startAuthLoop(username string, hostname string) {
    cmd := exec.Command("ssh", "-o", fmt.Sprintf("ProxyCommand bash -c \"source auth-loop.sh %s %s\"", username, hostname), "-i", authKeyCert, fmt.Sprintf("%s@%s", username, hostname))
    cmd.Env = append(os.Environ())
    cmd.Stdin = os.Stdin
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Start()
    cmd.Wait()
}
