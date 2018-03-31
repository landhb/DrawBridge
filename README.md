# Trigger

A Layer 4 Single Packet Authentication Module 

## Configuration & Generating an RSA Key

## Customizing a unique knock packet

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

[Here is a good short article on tcp flags if you're unfamiliar.](https://danielmiessler.com/study/tcpflags/) After you have a working BPF filter, you need to compile it and include the filter in the kernel module server-side. So to compile this filter:

```
tcpdump "tcp[tcpflags] == 28 and tcp[14:2] = 3104" -dd
```

which gives us:

```
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