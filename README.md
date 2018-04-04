![logo](https://github.com/landhb/Trigger/blob/master/img/logo.PNG?raw=true)

A layer 4 Single Packet Authentication (SPA) Module, used to conceal TCP ports on public facing machines and add an extra layer of security.

## Demo

## Easy Setup and Configuration

To compile either the client application or the kernel module simply cd into the respective directories and run make install. 

```bash
# on client machine
cd client
make install

# on server
cd kernel
make install
```

To automagically generate keys run the following on your client machine:

```bash
./gen_keys.sh
```

The output of the gen_keys.sh script will be two files: private.pem and public.der. Keep private.pem on your client machine and put a copy of public.der on the server in /etc/trigger. 

## Customizing a Unique 'knock' Packet

If you wish to customize your knock a little more you can edit the TCP header options in trigger.c. For instance, maybe you want to make your knock packet have the PSH,RST,and ACK flags set and a window size of 3104. Turn those on:

```c
// Flags
(*pkt)->tcp_h.fin = 0;   // 1
(*pkt)->tcp_h.syn = 0;   // 2
(*pkt)->tcp_h.rst = 1;   // 4
(*pkt)->tcp_h.psh = 1;   // 8
(*pkt)->tcp_h.ack = 1;   // 16
(*pkt)->tcp_h.urg = 0;   // 32


(*pkt)->tcp_h.window = htons(3104);
```

Then make sure you can create a BPF filter to match that specific packet. For the above we would have RST(4) + PSH(8) + ACK(16) = 28 and the offset for the window field in the TCP header is 14:

```
"tcp[tcpflags] == 28 and tcp[14:2] = 3104"
```

[Here is a good short article on tcp flags if you're unfamiliar.](https://danielmiessler.com/study/tcpflags/) After you have a working BPF filter, you need to compile it and include the filter in the kernel module server-side. So to compile this and place the output in kernel/listen.c in struct sock_filter code[]:

```
tcpdump "tcp[tcpflags] == 28 and tcp[14:2] = 3104" -dd
```

which gives us:

```c
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x50, 0, 0, 0x0000001b },
{ 0x15, 0, 3, 0x0000001c },
{ 0x48, 0, 0, 0x0000001c },
{ 0x15, 0, 1, 0x00000c20 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
```

And there you go! You have a unique packet that the Trigger kernel module will parse!


## Generating an RSA Key Pair Manually

First generate the key pair:

```
openssl genrsa -des3 -out private.pem 2048
```

Export the public key to a seperate file:

```bash
openssl rsa -in private.pem -outform DER -pubout -out public.der
```

If you take a look at the format, you'll see that this doesn't exactly match the kernel struct representation of a public key, so we'll need to extract the relevant data from the BIT_STRING field in the DER format:

```bash
vagrant@ubuntu-xenial:~$ openssl asn1parse  -in public.der -inform DER

0:d=0  hl=4 l= 290 cons: SEQUENCE
4:d=1  hl=2 l=  13 cons: SEQUENCE
6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
17:d=2  hl=2 l=   0 prim: NULL
19:d=1  hl=4 l= 271 prim: BIT STRING        <-------------------- THIS IS WHAT WE NEED
```

You can see that the BIT_STRING is at offset 19. From here we can extract the relevant portion of the private key format to provide the kernel module:

```bash
openssl asn1parse  -in public.der -inform DER -strparse 19 -out output.der
```

You'll notice that this is compatible with [RFC 3447 where it outlines ASN.1 syntax for an RSA public key](https://tools.ietf.org/html/rfc3447#page-44).

```bash
0:d=0  hl=4 l= 266 cons: SEQUENCE
4:d=1  hl=4 l= 257 prim: INTEGER           :BB82865B85ED420CF36054....
265:d=1  hl=2 l=   3 prim: INTEGER           :010001
```

If you need to dump output.der as a C-style byte string:

```bash
hexdump -v -e '16/1 "_x%02X" "\n"' output.der | sed 's/_/\\/g; s/\\x  //g; s/.*/    "&"/'
```
