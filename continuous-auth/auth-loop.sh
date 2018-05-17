AUTH_KEY_CERT="$HOME/.ssh/auth-key-cert.pub"
TOKEN_LIB="/usr/local/lib/libykcs11_YUBICO.dylib"
PRINCIPAL=$1
HOST=$2

function ssh-kill {
	sleep 10s
    conn=$(ps aux | grep "$1" | grep -v grep | awk '{print $2}') 
    kill $conn &> /dev/null 
    wait $conn &> /dev/null
}

function mux {
    SOCKET="$(mktemp /tmp/cont-auth-socket.XXXXXX)"
    PIPE=$SOCKET-pipe
    mkfifo $PIPE &> /dev/null
    rm $SOCKET &> /dev/null
    nohup nc -lU $SOCKET -k < $PIPE | nc localhost 22 > $PIPE & 
    echo "$SOCKET" 
}

function cleanup {
    SOCKET=$1
    PIPE=$2
    kill $(ps aux | grep "nc -lU $1 -k < $PIPE" | grep -v grep | awk '{print $2}') &> /dev/null
    kill $(ps aux | grep "nc localhost 22 > $PIPE" | grep -v grep | awk '{print $2}') &> /dev/null
    rm $SOCKET
    rm $PIPE
}

SOCKET="$(ssh -q -i $AUTH_KEY_CERT -o BatchMode=yes $PRINCIPAL@$HOST "$(typeset -f); mux" < /dev/null)"
while kill -0 $PPID > /dev/null
do
    ssh -q -i $AUTH_KEY_CERT -o BatchMode=yes -o ConnectTimeout=5s $1@$2 "$(typeset -f); ssh-kill 'nc -U $SOCKET'" &
    ssh -q -i $AUTH_KEY_CERT -o BatchMode=yes -o ConnectTimeout=5s $1@$2 "nc -U $SOCKET"
    if ! (lsusb | grep -q "Yubikey") &> /dev/null; then
        break
    fi
done
ssh -q -i $AUTH_KEY_CERT -o BatchMode=yes $PRINCIPAL@$HOST "$(typeset -f); cleanup $SOCKET $PIPE"

