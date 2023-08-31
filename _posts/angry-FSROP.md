---
title: '[angry-FSROP] Bypassing vtable Check in glibc File Structures'
date: 2022-10-22 15:20:00
tags:
- Linux
- glibc
- PWN 
- angr
---

# Introduction
The story began with a student, @Ramen, asking me about the status of file structure attacks nowadays two days ago. He told me there were no public attacks that grant PC-control solely from file structure attacks in glibc-2.35 and I was a bit skeptical about it because I have heard about many techniques that can successfully lead to shells in CTFs.

After reading all the writeups, it turned out he was right (I shouldn't have underestimated the technical skills of a blue-belt holder on pwn.college). These known techniques need to chain a ton of tricks together and the use of file structures are no longer as clean and powerful as in the past. (@angelboy's arbitrary read/write technique based on file structure buffers still works fine, but does not provide PC-control)

Then, I started wondering a higher-level question: with hooks obsolete (e.g. `__malloc_hook`, `__free_hook`) in the latest glibc, is there any clean way to obtain PC-control directly in libc?
Since I just finished my previous projects and my new projects haven't started yet, I'm basically free (Dobby is free!). So I dedicated a few hours to this question and resulted in a class of techniques that can grant us PC-control given 1. known libc base 2. a fully controlled file structure, despite the presence of vtable checks in glibc.

The story is so interesting that I have to share it.

Spoiler: the answer to life the universe and everything is ~~42~~ `angr`.

<!-- more -->

# Eternal war in File Structures

File structure (`FILE`) is a data structure provided by glibc to assist programmers in processing files. Internally, glibc has an extended data structure `struct _IO_FILE_plus` for the ease of implementation.
More specifically, `struct _IO_FILE_plus` simply adds a vtable to `FILE`:
```
struct _IO_FILE_plus {
    FILE file;
    const struct _IO_jump_t *vtable;
}
```

In the past (<= glibc-2.23), with a controlled file structure, we could just overwrite the vtable pointer to somewhere we control, (e.g. a heap address), and invoke corresponding file structure actions then we can get PC-control.
In glibc-2.24, the developers introduced a protection to this kind of attack:
```
static inline const struct _IO_jump_t *
IO_validate_vtable (const struct _IO_jump_t *vtable)
{
  /* Fast path: The vtable pointer is within the __libc_IO_vtables
     section.  */
  uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
  uintptr_t ptr = (uintptr_t) vtable;
  uintptr_t offset = ptr - (uintptr_t) __start___libc_IO_vtables;
  if (__glibc_unlikely (offset >= section_length))
    /* The vtable pointer is not in the expected section.  Use the
       slow path, which will terminate the process if necessary.  */
    _IO_vtable_check ();
  return vtable;
}
```
In short, this protection makes sure the `vtable` have to be within the `__libc_IO_vtables` section, or the process will exit.
Worse still, they also encrypt some function pointers that are inevitable in file structure so that PC-control cannot be obtained unless the encryption key is leaked (which is stored in thread local storage).

CTFers soon came up with a bypass. The key is that the check only makes sure the `vtable` is within the range, which means we can still misalign the `vtable` pointer so that different function pointers with `__libc_IO_vtables` section can be invoked. (Plz keep this in mind, this is important.)
In glibc-2.24, people noticed that some functions (e.g. `_IO_str_overflow`) use function pointers outside of the vtable, which could be used for getting PC-control as well as shown below:
```
int
_IO_str_overflow (_IO_FILE *fp, int c)
{
  ...
  new_buf = (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size);
  ...
}

```

But in glibc-2.28, these unchecked function pointers are removed (just to make CTFers lives harder).

So, is that still possible to get PC-control directly with a controlled file structure?

# Manual Auditing

My first thought was: there shouldn't be too many vtables in libc, so not too many function pointers, we can invoke from a controlled file structure (using the misaligned vtable), we could just disassemble all of them and search for `call`/`jmp` and see whether there are any missing checks.

Basically, there are only 81 unique function pointers in the libc vtable section. I disassembled all of them and all the indirect function calls that I checked were either encrypted or invoked from validated vtables.

The disassemby output can be found [here](https://github.com/Kyle-Kyle/blog/blob/master/_posts/resource/angry-fsrop/disassembly.txt).

For example, the following is the disassembly of `_IO_cookie_close`:
```
   7f890:       endbr64 
   7f894:       mov    rax, QWORD PTR [rdi+0x100]
   7f89b:       ror    rax, 0x11
   7f89f:       xor    rax, QWORD PTR fs:0x30
   7f8a8:       test   rax, rax
   7f8ab:       je     0x7f8c0
   7f8ad:       mov    rdi, QWORD PTR [rdi+0xe0]
   7f8b4:       jmp    rax   
   7f8b6:       cs nop WORD PTR [rax+rax*1+0x0]
   7f8c0:       xor    eax, eax
   7f8c2:       ret
```

`qword ptr [rdi+0x100]` is the encrypted function pointer, we need to either overwrite `fs:0x30` or leak it before we can get PC control. (In fact, this technique is known and is named [house-of-emma](https://www.anquanke.com/post/id/260614)).

So, this means we still can get PC-control with a controlled file structure, but need to have another primitive to overwrite or leak `fs:0x30`.

So not too bad.

<img src="https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/angry-fsrop/ok_with_this.gif" alt="rick-and-morty-Im-OK-with-this" height="400"/>

# Angr(y) Auditing

But man, this is lame. With control over file structure, such a complicated data structure, and we cannot even hijack the control flow directly?

With a little bit of thinking, I realized that this is a bounded model checking problem: given a fully controlled file structure, can we propagate the controlled data to `rip` through one of the 81 functions (with a fixed number of steps)?

Apparently, this question is something that `angr` is able to answer and it just happens that I am a ~~master~~ PhD of `angr`. So, I decided to give `angr` a shot.

<img src="https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/angry-fsrop/not_ok_with_this.gif" alt="rick-and-morty-Im-NOT-OK-with-this" height="400"/>

I wrote a quick `angr` script that used a region full of symbolic values as a file structure and tried to symbolically execute the 81 functions using the symbolic file structure as the argument. I expected this script to reach unconstrained states, which means it can propagate the symbolic data to `rip`.

And indeed, just within one minute, `angr` starts flooding the console with "unconstrained states" warnings. I manually checked one and it was `house-of-emma`.

This was encouraging but not so useful: we want to find new techniques directly from file structure attacks without other primitives. In other words, we want the PC-control to be a plain symbolic value instead of an AST tree.
Then I added a simple filter like `simgr.move("unconstrained", "bad", filter_func=lambda state: state.regs.pc.depth > 1)`, and went out for coffee. When I came back, `angr` found a path in `_IO_wfile_seekoff->_IO_switch_to_wget_mode->_IO_WOVERFLOW`. I manually confirmed this path works.

Cool! The script was still in a terrible state and it found a new technique already? I enhanced it a bit and let it run over-night. The next day, `angr` reported at least 9 new techniques.

I didn't triage all of them and also don't want to name all of them. So, I decided to call the class of techniques `angry-FSROP` (file structure ROP techniques discovered by `angr`).

The full script can be found [here](https://github.com/Kyle-Kyle/angry-FSROP/blob/main/angry-fsrop.py) (it is very dirty and can cause damage to your eyes. Proceed with caution, you have been warned).

# angry-FSROP Case Study

I wanted to make sure they actually work. So I picked the easiest case (by picking an `angr` state with the least variable numbers in the constraints, `len(state.solver._solver.variables)`) and manually confirmed it works.

The path of the chain is `_IO_wfile_overflow->_IO_wdoallocbuf->_IO_WDOALLOCATE->WJUMP0`. 

```
wint_t
_IO_wfile_overflow (FILE *f, wint_t wch)
{
  ...
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0)
  {
    if (f->_wide_data->_IO_write_base == 0)
    {
      _IO_wdoallocbuf (f);
      ...
    }
    ...
  }
  ...
}

void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF)
      return;
  ...
}
```

The reason why this path works is that somehow in `_IO_WDOALLOCATE (fp)`, which invokes a function pointer in `_wide_vtable` and `_wide_vtable` is not checked by `IO_validate_vtable` (`_wide_vtable` is part of `_IO_wide_data`, a field of `FILE`).

An example on how to craft the payload and a demonstration of this instance of angry-FSROP can be found in my [repo](https://github.com/Kyle-Kyle/angry-FSROP/tree/main/demo).

# PC2ROP

But how to ROP from the PC-control? Notice that `rdi` is also in our control (points back to the file structure itself), so what we actually have is `PC`+`rdi` control, which is more than enough to ROP.

One way to do it is using some gadgets such as the following (part of `getkeyserv_handle`) to propagate `rdi` to `rdx` then use the classic `setcontext` gadget to ROP.
```
mov    rdx,QWORD PTR [rdi+0x8];
mov    QWORD PTR [rsp],rax
call   QWORD PTR [rdx+0x20]
```

# Conclusion

I used `angr` to find a class of file structure attack techniques that can grant PC-control despite the presence of the vtable check.

I only manually verified one of them. If you verify more instances, please let me know :D

# Follow up
After the blog was posted, I was informed that there are existing techniques on getting PC-control using file structure: @roderick01 proposed [house-of-apple2](https://bbs.pediy.com/thread-273832.htm) a few months ago, which contains three chains (two are the same ones as what I manually validated) to achieve it. And all of the three relied on the fact that the `_wide_vtable` is not validated.

Then I got interested: among all the techniques (at least 9) that `angr` found, how many do not rely on the fact that `_wide_vtable` is not validated?
I did not have a direct way to measure it, so I used an indirect approach: how many symbolic states have constraints on `_wide_data` (the object that contains `_wide_vtable`) using the following snippet:
```
for func in state_dict:
    print(func)
    for idx, state in enumerate(state_dict[func]):
        if 'wide_data' not in state.solver._solver.variables:
            print(idx, state)
```

~~The result shows that all the states have constraints on `_wide_data`, which means it is likely that all of them get PC-control through `_wide_vtable`. In other words, if the developers add the vtable check to `_wide_vtable`, it is likely that all the techniques will be killed (but you never know whether `angr` will find something new after the patch ;) ).~~

# Follow up to the Follow up
It turns out my previous conclusion that all the chains found by `angr` rely on `_wide_data` is wrong. The reason why `_wide_data` exists in all the state constraints is that `angr` will concretize `_wide_data` to either NULL or a real pointer, which does not have to imply that the technique relies on `_wide_data`.

By removing the dependency on `_wide_data`(by concretizing it by ourselves), `angr` is still able to find 7 chains (which surprises me, it's just too many). One of them are exactly the same as @nobodyisnobody's [chain](https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022%2Fpwn%2Fbyor). I manually verified another starting from `_IO_file_finish` and it worked. The new script (that was used to solve a hacklu challenge) can be found [here](https://github.com/Kyle-Kyle/angry-FSROP/blob/main/hacklu_solve.py).

