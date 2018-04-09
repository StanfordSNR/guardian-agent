auth_key_cert="$HOME/.ssh/auth-key-cert.pub"
token_lib="/usr/local/lib/libykcs11_NOTALINK.dylib"
PRINCIPAL=$1
HOST=$2

function ssh-kill {
	sleep 10s
	while kill -0 $PPID > /dev/null &> /dev/null
	do
        kill $(ps aux | grep "$1" | grep -v grep | awk '{print $2}') &> /dev/null
        sleep 10s
	done
}

function mux {
    SOCKET="$(mktemp /tmp/cont-auth-socket.XXXXXX)"
    PIPE=$SOCKET-pipe
    mkfifo $PIPE &> /dev/null
    rm $SOCKET &> /dev/null     # take this out when dynamically choose
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

SOCKET="$(ssh -q -i $auth_key_cert -o BatchMode=yes $PRINCIPAL@$HOST "$(typeset -f); mux" < /dev/null)"
ssh-kill "ssh -q -i $auth_key_cert -o BatchMode=yes -o ConnectTimeout=5s $1@$2 nc -U $SOCKET" &
while kill -0 $PPID > /dev/null
do
	if ! ssh -q -i $auth_key_cert -o BatchMode=yes -o ConnectTimeout=5s $1@$2 nc -U $SOCKET
    then
        sleep 1s   # wait to retry to see if key inserted
        if (lsusb | grep -q "Yubikey") &> /dev/null
        then
            eval `ssh-agent -s` > /dev/null
            ssh-add -s $token_lib > /dev/null
        fi
    fi
done
ssh -q -i $auth_key_cert -o BatchMode=yes $PRINCIPAL@$HOST "$(typeset -f); cleanup $SOCKET $PIPE"

