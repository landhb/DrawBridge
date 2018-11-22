#!/bin/bash

printf "[*] Generating private key...\n"
openssl genrsa -des3 -out private.pem 2048

printf "[*] Generating public key...\n"
openssl rsa -in private.pem -outform DER -pubout -out public.der


openssl asn1parse  -in public.der -inform DER -strparse 19 -out output.der


echo  "void * public_key = " > key.h
hexdump -v -e '16/1 "_x%02X" "\n"' output.der | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/' >> key.h
echo -n ";" >> ./key.h

rm public.der
rm output.der


printf "[+] Created private.pem and key.h\n"