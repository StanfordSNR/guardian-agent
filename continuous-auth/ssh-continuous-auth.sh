# Already need to have added PKCS11 library for token and have a pub key

token_lib="/usr/local/lib/libykcs11_NOTALINK.dylib"
auth_key_cert="$HOME/.ssh/auth-key-cert.pub"
ca_pub_key="/etc/ssh/ssh-ca-key.pub"
auth_pub_key="$HOME/.ssh/auth-key.pub"

principal="$(cut -d'@' -f1 <<<$1)"
host="$(cut -d'@' -f2 <<<$1)"

function mux {
    port=2001                   # Port to forward to
    UNIX_DOMAIN_SOCKET="/tmp/socket"
    pipe=$UNIX_DOMAIN_SOCKET-pipe
    mkfifo $pipe &> /dev/null
    rm $UNIX_DOMAIN_SOCKET &> /dev/null     # take this out when dynamically choose
    nohup nc -lU $UNIX_DOMAIN_SOCKET -k < $pipe | nc localhost 22 > $pipe &
}

function cleanup {
    kill $(ps aux | grep "nc -lU $1 -k < $1-pipe" | grep -v grep | awk '{print $2}') &> /dev/null
    kill $(ps aux | grep "nc localhost 22 > $1-pipe" | grep -v grep | awk '{print $2}') &> /dev/null
    # do netstat for unix domain sockets, search for it and find process and kill it, and delete unix domain socket 
}

ssh-keygen -D $token_lib -s $ca_pub_key -I $USER -n $principal $auth_pub_key &> /dev/null # used to be -I user 

ssh -q -i $auth_key_cert -o BatchMode=yes $principal@$host "$(typeset -f); mux"
ssh -o 'ProxyCommand bash -c "source auth-loop.sh %r %h"' -o ConnectTimeout=5s -i $auth_key_cert $1
ssh -q -i $auth_key_cert -o BatchMode=yes $principal@$host "$(typeset -f); cleanup /tmp/socket"

rm $auth_key_cert
