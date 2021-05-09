---
title: '[WCTF-2020] - machbooks'
date: 2020-11-20 11:54:15
tags:
- CTF
- macOS
- PWN
---

# Introduction
Despite I've been insanely busy recently, I still decided to play WCTF for bit and managed to solve one challenge called `machbooks`. 
As the name suggests, it is a Mach-O challenge. Mach-O is the binary format on macOS(like ELF on Linux). Mach-O challenges are rare in CTF community. So, it intereted me the moment I saw the challenge name (In fact, I didn't plan to play the CTF at all, lol).
Because of the rarity of Mach-O challenges, some CTF-ready tools do not work on the binary format and not many people know how to deal with Mach-O binaries at all. Those may be the reasons why there was only one solve during the game.
Luckily, I was exposed to Mach-O by a challenge called `applepie` during 0CTF-2019. And that experience gave me an edge to finish the only solve to the challenge during the game.

<!-- more -->

To contribute to the CTF community, I'd like to share my solution and share my knowledge about Mach-O. And hopefully we are going to have more diversity for PWN challenges.

# Background
Before we dive into the details of the challenge, we'd need to know some background info about how things work on macOS. What I'm going to describe below is based on macOS 10.15.7.

Basically, everything works similarly to how ELFs work on Linux. With several key differences.

## Fat Binaries
Some Mach-O binaries are fat binaries(universal executables). These binaries can run on multiple architecture.
In fact, they basically embed multiple binaries for multiple architectures inside one single binary. My guess is during runtime, only the correct binary for the runtime architecture will be mapped.
For details about fat binaries, you can checkout the awesome blog [here](https://www.symbolcrash.com/2019/02/26/mach-o-universal-fat-binaries/).

Fat binary is not a common binary format that we've seen in CTFs. This introduces troubles for some tools.

## ROP gadget
In the CTF community, people are spoiled. The task of finding ROP gadgets is as simple as running `ROPgadget`, `ropper` or other gagdet finders on the target ELF binaries.

However, again, due to the rarity of Mach-O challenges, these tools don't support finding gadgets on Mach-O binaries well.
Both `ROPgadget` and `ropper` are able to find gadgets on single architecture Mach-O binaries but fail to do that on fat binaries.

Which means, we can easily find gadgets in the challenge binaries but will have a hard time finding gadgets in libraries because all system libraries on macOS are fat binaries.

To make things worse, the compilation of Mach-O has been somehow tuned so that the output binaries are less likely to contain some good gadgets like we do in ELF. For example, `pop rdi; ret` is very common in ELF. However, it does not exist in our challenge binary and not even in `libsystem_c.dlylib`(similar to `libc.so.6` on Linux, so I'll call it libc from here).

To find good gadgets, my approach was to modify the source code of `ROPgadget` so that it always treats it as 64bit binary when it sees a Mach-O binary and I make it only analyzes my hardcoded segment(`.text` segment of 64bit binary ofc.). It's a dirty method, but it worked pretty well.

## ASLR+PIE
On macOS, ASLR and PIE exist and work almost the same as what we have on Linux.

Except that:

1. library addresses are randomized during boot time only. Which means if we leak the base address of libc once, we can use it directly on the target machine in later exploits. [Here](https://stackoverflow.com/questions/12824045/what-exactly-is-randomized-with-aslr-in-macos-x-and-ios/18715045#18715045) is a reference about ASLR and PIE on macOS.

2. PIE can be disabled by changing header flags. PIE are controlled by a Mach-O header, by flipping the header, we can disable PIE. [here](https://github.com/sskaje/disable_aslr) and [here](https://github.com/thlorenz/chromium-build/blob/master/mac/change_mach_o_flags.py) are some scripts that can be used to turn off PIE.

## Debugging
Unfortunately, `gdb` does not work properly on macOS. There are some serious attempts to make it work but I think all of them suffer some issues.

The debugger shipped on macOS is `lldb`. Its commands are different from `gdb`'s. But once you get used to it, you will find them much easier to remember than `gdb`'s. (Personally, I think `gdb` is like `pwndbg` and `lldb` is like `gef`. Because `gdb` and `pwndbg` use a flat command scheme while `lldb` and `gef` use a structured command scheme.)

On `gdb`, we have some awesome plugin scripts like `gef` and `pwndbg`. However, we don't have many of those on `lldb`. The best I found was [voltron](https://github.com/snare/voltron). But I failed to make it work on my machine.

Instead, I have a tiny script that is basically a copy-paste of part of `gef`'s source code(I'm a fan of `gef`). It only has three commands: `vmmap`, `xinfo`, `search-pattern`. Although it is small, it helped me a lot during the debugging.

# Recon

Finally, let's have a look at the challenge `machbooks` itself.

The challenge is a menu-based challenge like it always is for heap challenges, except that it is not a heap challenge this time :). 

It mimics the process of writing books on macOS. And the book data structure is defined as follow:

```00000000 book_t          struc ; (sizeof=0x40, mappedto_23)
00000000 name            db 32 dup(?)
00000020 flag_ptr        dq ?                    ; offset
00000028 load_stream     dq ?                    ; offset
00000030 edited          dq ?
00000038 chapter_head    dq ?                    ; offset
00000040 book_t          ends
00000040
```

The data structure is almost self-explanatory. But one thing worth noticing, `flag_ptr` is a pointer pointing to the status of the book. `*flag_ptr & 0xf` records whether the book is in use. `*flag_ptr & 0xf0` records whether the book is removed.

You can:

1. create a book, basically to fill the book data structure and initialize `*flag_ptr` to 1.
2. read a book to print the name and chapters of a book
3. edit a book's name, but one book can be edited only once
4. add a chapter. 
5. remove a book, to perform `| 0x10` on the book's `*flag_ptr`.
6. serialize/deserialize a book to/from files. (They call it upload to/download from the cloud, very realistic :))

One thing worth noticing, the book array and status array(`flag_ptr` points to this array) are not global variables, they reside on heap. And they are adjacent to each other.

# Vulnerability
The vulnerability is an off-by-one in the name of the book during serialization.
Normally, 0x1f bytes will be written into `book->name`. And since `book->name` was initialized to be filled with 0s, it is nicely NULL-terminated.
But look like that the `dump` function during serialization:
```
int __fastcall dump(char *buf, unsigned int len, FILE *stream)
{
  unsigned int i; // [rsp+4h] [rbp-1Ch]
  for ( i = 0; i < len && buf[i]; ++i )
    fputc(buf[i], stream);                       // fputc ?? null byte??
  return fputc(10, stream);                      // no longer null-terminated
}
```
It is called with `dump(book->name, 0x20, stream)`. And the last `\n` will overwrite the null-byte and connect `book->name` and `book->flag_ptr`.

# Primitive - write-x-where
With what we have so far, we can leak a heap pointer easily. And that pointer is pointing to the status array. And notice that the book array and the status array are adjacent to each other, we can calculate and know the address of the book array too.

We have heap leak now. Good. But how to proceed?
Here, the `edit_book_name` function comes into play:
```
void __fastcall edit_book_name()
{
  unsigned int v0; // eax
  book_t *book; // [rsp+8h] [rbp-18h]
  unsigned int idx; // [rsp+1Ch] [rbp-4h] BYREF
  printf("Book index: ");
  scanf("%u", &idx);
  if ( idx >= 6 || books[(unsigned __int64)idx].edited )
  {
    puts("Invalid index");
  }
  else
  {
    printf("Book new name: ");
    book = &books[(unsigned __int64)idx];
    v0 = strlen(book->name);
    readn(book->name, v0);
    books[(unsigned __int64)idx].edited = 1LL;
  }
}
```
Notice that the length to edit is determined by `strlen` and that `book->name` is no longer NULL-terminated. Combining both, we can overwrite `book->flag_ptr`.

At this moment, we can overwrite the `flag_ptr` and overwrite null-byte anywhere with an uncontrolled non-NULL value by changing the status of the book. (because the status of a book is `*book->flag_ptr`).

Now, the plan is obvious. There is a `load_stream` pointer after `flag_ptr`. `load_stream` is a pointer of type `FILE *` used to `reload` the book. If we can overwrite that, we may be able to perform a file structure attack although it's not clear how that works on macOS. Anyway, this challenge is designed by `Balsn` which means file structure attack should be the intended solution.

Overwriting `load_stream` is not hard, we simply need to use the the `write-x-where` primitive to change the two NULL bytes in `flag_ptr` to non-NULL values and then call `edit` again.

The problem is: what to write? We only have heap leak at this moment. Although we don't know how file structure works on macOS ,one thing is for sure: if we want to fake a file structure, we need executable pointers which we don't have.

# Knock, Knock. Gift from macOS: libc .data address
What should we do here? Can we partial overwrite `load_stream` to make it do something funky? But where is this `load_stream` in the first place?
Remember my debug script has `xinfo`? I ran `xinfo` on `load_stream`. And to my surprise, `load_stream` does not reside on heap, it's on the `.data` segment of `libsystem_c.dylib`(libc)! lol. I have no idea how that works, what will happen if we have too many `FILE` structure that `.data` cannot hold?

But anyway, we know `load_stream` is a libc `.data` segment pointer. Recall what we know about macOS, library address is randomized during boot. Which means the pointer will stay the same across runs.
What we can do here is to perform byte-wise bruteforce to leak the whole pointer:

1. overwite 1 byte of the pointer
2. trigger `reload` function to make the program use `load_stream` pointer. If the overwritten 1 byte is different from the original byte, it's very likely that it will point to something that's not a FILE structure. And notice that FILE structure contains a lot of function pointers, if those function pointers are wrong, it is likely going to crash.

By bruteforcing the address of `load_stream` one byte at a time, we can leak the whole pointer easily..... at least in theory. The only difficulty here is that the server was in China and the connection to the server was sooooooo slow from outside of China. It takes forever to leak one byte.

So, I asked one of my friends, @sanebow. He is as magical as doraemon. Whenever I'm in need of something, he always has it. Without questions, he lent me his server inside China and even gave me `sudo` privilege. Thanks man!

# file structure attack on macOS😱
Now we have libc address, we should be able to perform file structure attack by overwriting the `load_stream` with the address of fake file structure.

But there are two questions:

1. where to place the fake file structure

2. what should the fake file structure look like

For the first question, the most intuitive answer is to use the `chapter` field. It's basically 0x520 bytes of user controlled data. We may use that to craft our payload. Hmmm, it will work on glibc's ptmalloc but not macOS's magazine allocator. Because of size differences, book array is placed in `MALLOC_TINY` segment and chapters are placed in `MALLOC_SMALL` segment. The offset between `MALLOC_TINY` and `MALLOC_SMALL` is randomized each run. Basically, this approach is dead.

Notice that `book->name` has length 0x20, if we are lucky, we may make our fake file structure overlapping with the book array and use the `name` field to control function pointers. But this totally depends on how `FILE` structure looks like on macOS and how all the functions are implemented.

Now the only question left: what does `FILE` structure look like on macOS?
Thankfully, IDA Pro, our beloved friend, knows this. Opening `libsystem_c.dylib` in IDA. We can recover its definition:
```
00000000 FILE            struc ; (sizeof=0x98, align=0x8, copyof_106)
00000000 _p              dq ?                    ; offset
00000008 _r              dd ?
0000000C _w              dd ?
00000010 _flags          dw ?
00000012 _file           dw ?
00000014                 db ? ; undefined
00000015                 db ? ; undefined
00000016                 db ? ; undefined
00000017                 db ? ; undefined
00000018 _bf             __sbuf ?
00000028 _lbfsize        dd ?
0000002C                 db ? ; undefined
0000002D                 db ? ; undefined
0000002E                 db ? ; undefined
0000002F                 db ? ; undefined
00000030 _cookie         dq ?                    ; offset
00000038 _close          dq ?                    ; offset
00000040 _read           dq ?                    ; offset
00000048 _seek           dq ?                    ; offset
00000050 _write          dq ?                    ; offset
00000058 _ub             __sbuf ?
00000068 _extra          dq ?                    ; offset
00000070 _ur             dd ?
00000074 _ubuf           db 3 dup(?)
00000077 _nbuf           db ?
00000078 _lb             __sbuf ?
00000088 _blksize        dd ?
0000008C                 db ? ; undefined
0000008D                 db ? ; undefined
0000008E                 db ? ; undefined
0000008F                 db ? ; undefined
00000090 _offset         dq ?
00000098 FILE            ends
```
It still doesn't make sense because the structure has very bad naming scheme. But combined with memory examination, we know that `_close`, `_read`, `_seek`, `_write` are fucntion pointers.
By aligning the fake file structure carefully, we can successfully make `_close` overlap with `book->name` and successfully obtain RIP control by calling `fclose` on `load_stream` which is now our controlled fake file structure!

Even more amazingly, `_close` takes `_cookie` as the argument. By overwriting `_cookie` and `_close`, we can have both RIP and RDI control!!!

# HOW2ROP
Now we have both RIP and RDI control, `system("/bin/sh")` you may scream. Ooops, but no. The chalenge is sandbox-ed. The only program we can execute is the challenge itself. The only choice left is to ROP.

But how to ROP from a RIP+RDI control? On Linux, there is a famous trick about using `setcontext+53` gadget to set all registers, including RIP and RSP. In that way, we can easily ROP.

We don't know any tricks like that on macOS, but we know that `setcontext` is a function that is meant to set registers. Maybe we can perform the same trick on macOS. By some searching, we can locate `setcontext` in `libsystem_platform.dylib`(I'll call it libplatform from here). And there is a gadget looking like this in `setcontext`:
```
mov     rbx, [rdi+18h]
mov     r12, [rdi+70h]
mov     r13, [rdi+78h]
mov     r14, [rdi+80h]
mov     r15, [rdi+88h]
mov     rsp, [rdi+48h]
mov     rbp, [rdi+40h]
xor     eax, eax
jmp     qword ptr [rdi+90h]
```
Now the plan is clear, set RIP to a `ret` gadget and set RSP to our fake stack and then ROP!

# Hello, libplatform
There are two problems though:

1. We don't know where it is mapped remotely.

2. libsystem is not give to us as a known library, we don't know whether the remote one is the same as the local one.

The first problem can be resolved by finding a symbol defined in libplatform and used in libc. We can find these symbols by reading the `Import` section of libc in IDA. Remember we have RIP and RDI control? We can use that to call `puts` on the function of choice to leak address of libplatform.

Using the similar method, we are able to leak libplatform itself and make sure the gadget is there.

# 5-gadget ROP

Now with every problem resolved, we are able to ROP. But we can only place our payload at`book->name`, which has size 0x20, even if we overwrite `flag_ptr` too, that's 0x28 bytes, which means 5 gadgets.

How to ROP with 5 gadgets? Easy, you `pop rdi, <stack_ptr>; jmp gets`. That's just 3 gadgets. The plan is good but the reality is that `gets` does not read data at all. I have no idea why but I think it may have something to do with my fake file structure and the fact `gets` is obsolete on macOS. It was already 3-4am in the morning and my brain was too dead to single-step through `gets` to figure out why. So, I gave up this plan.

Now what? 5 gadgets to call `read` function? That's like a mission impossible. One of the possibility is that we can chain several `book->name` together by `pop rsp, <next rsp>` or `add rsp, <value>`. But this approach is hard because:

1. many `book->name` are used for fake file structure and `setcontext` payload. There are not many bytes available for ROP chain.

2. there are some gadget missing in libc. For example, there is no `pop rdi; ret`, we have to use `pop rdi; pop rbp; ret`. They are kind of the same but that means 1 less gadget we can use. And the most concerning fact is: there is no `pop rdx` usable at all. we have to chain several gadgets to set RDX which takes even more gadgets.

I got stuck here for a while. Until I found a magic gadget in libplatform(without a working `ROPgadget`, I can never do this).
This is part of the function `__ctx_start`:
```
pop     rax
pop     rdi
pop     rsi
pop     rdx
pop     rcx
pop     r8
pop     r9
call    rax
```
Now with 4 gadgets, we can call `read`, overwrite everything and really ROP to read the flag.

# GG! ... ? wait a second.

We have finished everything and the exploit works locally stably. Now it's time to launch the attack remotely.
And then.... CRASH!

What's happening? We are not making any assumption that may be false on another machine, right?
(Hmmm. As a reader, did you notice that whenever I talk about the libc leak, I always say something like libc `.data` pointer)

On macOS, `.text` segment and `.data` segment are mapped separately, there is a huge offset between them. However, the offset stays the same across boots. I rebooted my machine several times to confirm this. So, I took it for granted that the offset is the same for all machines. However, after obtaining a memory mapping of @publicqi's machine. I noticed that the offset may stay the same on the same machine across boots, but the offset may be different for different machines.

Although there may be a difference between the offsets, but the difference is not huge. What we can do is to try different slides while trying to call `puts("/bin/sh")` by using the RIP+RDI control. If we successfully receive `/bin/sh` as the output, that means we guess the remote offset correctly. In this case, the difference between the remote offset and the local offset is -0x66000(page size aligned) which didn't take much time to figure out.

# Really GG
At this point, the challenge is solved.
It was a fun run and took a whole night of sleep away from me.
Now I'm more confident about macOS exploitation and hope to see more macOS challenges in the future.
