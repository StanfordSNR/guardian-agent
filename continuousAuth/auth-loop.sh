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
    PIPE=$SOCKET-pipe
    kill $(ps aux | grep "nc -lU $1 -k < $PIPE" | grep -v grep | awk '{print $2}') &> /dev/null
    kill $(ps aux | grep "nc localhost 22 > $PIPE" | grep -v grep | awk '{print $2}') &> /dev/null
    rm $SOCKET
    rm $PIPE
}

USER=$1
HOST=$2
STDIN_PIPE=$3
SSH_INPUT_PIPE=$4
SOCKET="$(ssh -q -i ~/.ssh/auth-key-cert.pub -o BatchMode=yes $USER@$HOST "$(typeset -f); mux" < /dev/null)"
while kill -0 $PPID > /dev/null; do
    go run conn.go $USER $HOST $SOCKET $STDIN_PIPE $SSH_INPUT_PIPE
    if ! kill -0 $PPID > /dev/null; then 
        break
    fi
    eval `ssh-agent -s` > /dev/null
    ssh-add -s /usr/local/lib/libykcs11_YUBICO.dylib > /dev/null
done
ssh -q -i ~/.ssh/auth-key-cert.pub -o BatchMode=yes $USER@$HOST "$(typeset -f); cleanup $SOCKET"
