#! /bin/sh
cd agent && go build
cd ../client && go build
cd ../sshfwd && go build
cd ../sshfwdstub && go build
cp sshfwdstub ~/
cd ../
