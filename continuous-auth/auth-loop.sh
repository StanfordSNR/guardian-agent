auth_key_cert="$HOME/.ssh/auth-key-cert.pub"
port=2001
token_lib="/usr/local/lib/libykcs11_NOTALINK.dylib"
UNIX_DOMAIN_SOCKET="/tmp/socket"

function ssh-kill {
	sleep 10s
	while kill -0 $PPID > /dev/null &> /dev/null
	do
        kill $(ps aux | grep "$1" | grep -v grep | awk '{print $2}') &> /dev/null
        sleep 10s
	done
}

ssh-kill "ssh -q -i $auth_key_cert -o BatchMode=yes -o ConnectTimeout=5s $1@$2 nc -U $UNIX_DOMAIN_SOCKET" &
while kill -0 $PPID > /dev/null
do
	if ! ssh -q -i $auth_key_cert -o BatchMode=yes -o ConnectTimeout=5s $1@$2 nc -U $UNIX_DOMAIN_SOCKET
    then
        sleep 1s   # wait to retry to see if key inserted
        if (lsusb | grep -q "Yubikey") &> /dev/null
        then
            eval `ssh-agent -s` > /dev/null
            ssh-add -s $token_lib > /dev/null
        fi
    fi
done

