#Generate authentication key
yubico-piv-tool -s 9a --touch-policy=never --pin-policy=never -k $MG_PIN -a generate -o auth-key.pem
yubico-piv-tool -a selfsign-certificate -s 9a -S "/CN=SSH key/" -i auth-key.pem -o auth-cert.pem
yubico-piv-tool -a import-certificate -s 9a -k $MG_PIN -i auth-cert.pem

# Generate certificate authority
yubico-piv-tool -s 9c --touch-policy=always --pin-policy=never -k $MG_PIN -a generate -o ca-key.pem
yubico-piv-tool -a selfsign-certificate -s 9c -S "/CN=SSH key/" -i ca-key.pem -o ca-cert.pem
yubico-piv-tool -a import-certificate -s 9c -k $MG_PIN -i ca-cert.pem

#Output two generated keys
ssh-keygen -D /usr/local/lib/libykcs11_NOTALINK.dylib -e
