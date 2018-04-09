# Already need to have added PKCS11 library for token and have a pub key

token_lib="/usr/local/lib/libykcs11_NOTALINK.dylib"
auth_key_cert="$HOME/.ssh/auth-key-cert.pub"
ca_pub_key="/etc/ssh/ssh-ca-key.pub"
auth_pub_key="$HOME/.ssh/auth-key.pub"

principal="$(cut -d'@' -f1 <<<$1)"
host="$(cut -d'@' -f2 <<<$1)"

ssh-keygen -D $token_lib -s $ca_pub_key -I $USER -n $principal $auth_pub_key &> /dev/null # used to be -I user 

ssh -o 'ProxyCommand bash -c "source auth-loop.sh %r %h $SOCKET"' -o ConnectTimeout=5s -i $auth_key_cert $1

rm $auth_key_cert
