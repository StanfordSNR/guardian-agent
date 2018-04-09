# Already need to have added PKCS11 library for token and have a pub key

TOKEN_LIB="/usr/local/lib/libykcs11_NOTALINK.dylib"
AUTH_KEY_CERT="$HOME/.ssh/auth-key-cert.pub"
CA_PUB_KEY="/etc/ssh/ssh-ca-key.pub"
AUTH_PUB_KEY="$HOME/.ssh/auth-key.pub"

principal="$(cut -d'@' -f1 <<<$1)"
host="$(cut -d'@' -f2 <<<$1)"

if [ ! -f $AUTH_KEY_CERT ]
then
    ssh-keygen -D $TOKEN_LIB -s $CA_PUB_KEY -I $USER -n $principal $AUTH_PUB_KEY &> /dev/null # used to be -I user 
fi

ssh -o 'ProxyCommand bash -c "source auth-loop.sh %r %h $AUTH_PUB_KEY"' -o ConnectTimeout=5s -i $AUTH_KEY_CERT $1

if ! kill -0 $(ps aux | grep "ssh .* -i $AUTH_KEY_CERT" | grep -v grep | awk '{print $2}') &> /dev/null
then
    rm $AUTH_KEY_CERT
fi
