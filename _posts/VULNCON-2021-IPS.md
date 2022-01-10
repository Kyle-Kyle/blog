---
title: '[VULNCON 2021] - IPS'
date: 2022-01-09 18:59:15
tags:
- CTF
- PWN
- Linux
- kernel
---

# Introduction
Last December (which is a month ago), I learnt that there was a Linux kernel CTF challenge, called IPS, unsolved during VULNCON 2021.
At that moment, I was struggling exploiting the first bug that we eventually used to pwn GKE for kCTF and I thought it would be great to solve a CTF challenge and regain some confidence in kernel exploitation.

However, I struggled a little bit again with the CTF challenge (because I was and still am dumb) and finally solved it with an unintended solution.
Even though my solution was much harder than the intended solution, it was the first blood for this challenge.

<!-- more -->

# Challenge
Now let me briefly discribe what kind of challenge it is.

Different from normal Linux kernel challenges where players deal with compiled kernel modules, this challenge implements a new system call `ips` and the source code of this system call is given. The source code is quite short, interested readers can find the source code [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/vulncon21_ips/ips.c).

Basically, it implements a service that allows users to allocate/remove/edit/copy some data in kernel space (just like heap challenges in userspace lol).
The logic looks like this:
~~~
SYSCALL_DEFINE2(ips, int, choice, userdata *, udata) {
  char data[114] = {0};
  if(udata->data && strlen(udata->data) < 115) {
    if(copy_from_user(data, udata->data, strlen(udata->data))) return -1;
  }
  switch(choice) {
    case 1: return alloc_storage(udata->priority, data);
    case 2: return remove_storage(udata->idx);
    case 3: return edit_storage(udata->idx, data);
    case 4: return copy_storage(udata->idx);
    default: return -1;
  }
}
~~~

The data, called `chunk`, stored in kernel space is described as follow:
~~~
typedef struct {
  void *next;
  int idx;
  unsigned short priority;
  char data[114];
} chunk;
~~~
Although there are several attributes such as `next`, `idx`, and `priority`, which makes it complicated, they actually have any no meaningful impact in the challenge. The only thing interesting is `data`, which is some content fully controlled by users. (I later learnt that @kileak used the `next` pointer for info leak, you can find his blog post [here](https://kileak.github.io/ctf/2021/vulncon-ips/)).


Although the `next` pointer defined in `chunk` makes it appear to be stored as a list, it is actually stored in an array defined as a global variable: `chunk *chunks[MAX] = {NULL};` (`MAX` is 16)
Each time the user calls `alloc_storage`, it will pick the first index where `chunks[idx]` is `NULL` for use using the funciton `get_idx`. Each time the user wants to remove/edit/copy a certain chunk, it will make sure the index is valid by calling the `check_idx` function.
~~~
int get_idx(void) {
  int i;
  for(i = 0; i < MAX; i++) {
    if(chunks[i] == NULL) {
      return i;
    }
  }
  return -1;
}

int check_idx(int idx) {
  if(idx < 0 || idx >= MAX) return -1;
  return idx;
}
~~~

# Vulnerabilities
## Bug 1
As a veteran in CTFs, my instinct told me there must be something wrong with the `copy` functionality, or it should be just alloc/edit/remove.
It turned out I was right.
~~~
int copy_storage(int idx) {
  if((idx = check_idx(idx)) < 0) return -1;
  if(chunks[idx] == NULL) return -1;

  int target_idx = get_idx();
  chunks[target_idx] = chunks[idx];
  return target_idx;
}
~~~
Looking at the code, I immediately noticed that the `copy` functionality basically copies a user-decided pointer (`idx` is user input) to a new index. It is likely that there can be a UAF situation if the the copyed pointer is not properly handled during `remove`.
~~~
int remove_storage(int idx) {
  if((idx = check_idx(idx)) < 0) return -1;
  if(chunks[idx] == NULL) return -1;

  int i;
  for(i = 0; i < MAX; i++) {
    if(i != idx && chunks[i] == chunks[idx]) {
      chunks[i] = NULL;
    }
  }

  kfree(chunks[idx]);
  chunks[idx] = NULL;

  return 0;
}
~~~
But no, `remove_storage` properly handles the copied pointers by clearing the copied versions before freeing the target pointer, so no UAF :(
So, what's the issue with `copy_storage`? Looking closely, I realized that `get_idx` can return `-1` if it is called when the chunk array is full, which becomes `chunks[-1] = chunks[idx]`.
This is an underflow in global variables, good, right? But not really.
The bug does not help the exploitation because 1. it does not overwrite any important data 2. all indices passed to `copy/remove/edit` will be sanitizied and `alloc` does not take index argument at all.

## Bug 2
I got stuck here for a while and didn't know how to proceed. I eventually decided to give up and started doing my research work. Luckily, I somehow managed to finish that day's work earlier than I expected, so I picked up the challenge again and immediately noticed something fishy.
`edit_storage` is defined as follow:
~~~
int edit_storage(int idx, char *data) {
  if((idx = check_idx(idx)) < 0);
  if(chunks[idx] == NULL) return -1;

  memcpy(chunks[idx]->data, data, strlen(data));

  return 0;
}
~~~
It appears that it also sanitizes the `idx` argument at the first glance. But look closer....... WTF??? It does not return even if the check fails???
Astonishment aside, this bug allows attackers to use the stored pointer at index `-1` from Bug 1.

# Exploitation

## Primitive
Combining Bug 1&2 together, it is clearly a UAF scenario.
One can copy a pointer, let's say `chunks[idx]`, to `chunks[-1]`, free `chunks[idx]` such that `chunks[-1]` becomes a dangling pointer, and then finally edit `chunks[-1]` to achieve UAF-write in `kmalloc-128` (the cache that `chunk` belongs to)

## Protections
Once I found the usable primitive, I started checking the protections applied in the challenge and deciding the exploitation stategies.

I checked the challenge start script and found out that `KASLR` is on and the author appends `+smap +smep` to the kernel arguments. However, the author does not specify cpu choices, which means QEMU will use its own emulated cpu to run the kernel. And by default, the cpu does not support `SMEP`/`SMAP`. So even though the kernel will try to enable `SMEP`/`SMAP`, it cannot succeed on a cpu that does not support them. As a result, the kernel will be run without these two protections.

After understanding the protection, the exploitation plan is clear: leak a kernel pointer to defeat KASLR and then overwrite a function pointer to perform ret2usr.

## OOB-Read
With the UAF primitive in hand, I decided to try out the `msg_msg` attack first to get info leak.
This is an attack that has been quite popular among Linux kernel exploit writers for a while.
It provides immediate OOB-Read and Arbitrary-Free primitive ([source1](https://syst3mfailure.io/wall-of-perdition), [source2](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)). It has also been demonstrated to be able to used to gain Arbitrary-Read/Write in some settings ([source1](https://syst3mfailure.io/wall-of-perdition), [source2](https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html)).

I'll only briefly talk about how this attack works here, interested readers can follow the links provided above for further readings.

`struct msg_msg` is defined like this:
~~~
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
~~~
They look like this in memory:
~~~
0xffff96daced9ba80:	0xffff96daced5a8c0	0xffff96daced5a8c0 <- m_list
0xffff96daced9ba90:	0x4141414141414141	0x0000000000000050 <- m_type and m_ts
0xffff96daced9baa0:	0x0000000000000000	0xffff96daced92b50 <- next and security
0xffff96daced9bab0:	0x4141414141414141	0x4141414141414141 <- actually message content starting from here
0xffff96daced9bac0:	0x4141414141414141	0x4141414141414141
0xffff96daced9bad0:	0x4141414141414141	0x4141414141414141
0xffff96daced9bae0:	0x4141414141414141	0x4141414141414141
0xffff96daced9baf0:	0x4141414141414141	0x0000000000000000
0xffff96daced9bb00:	0x0000000000000000	0x0000000000000000
0xffff96daced9bb10:	0x0000000000000000	0x0000000000000000
0xffff96daced9bb20:	0x0000000000000000	0x0000000000000000
0xffff96daced9bb30:	0x0000000000000000	0x0000000000000000
~~~
`struct msg_msg` is a header object that describes a message in the System V message IPC system.
It is allocated together with the actual content of the message. When the message itself is too long, the message content will be segmented: the first segment will be right after the header, the other segments will be chained as a linked list using the `next` attribute.

In this blog, I will refer to `struct msg_msg` as "message header" and the header+content as "msg_msg object" since they are allocated together.

The allocation code looks like this:
~~~
static struct msg_msg *alloc_msg(size_t len)
{
	struct msg_msg *msg;
	struct msg_msgseg **pseg;
	size_t alen;

	alen = min(len, DATALEN_MSG);
	msg = kmalloc(sizeof(*msg) + alen, GFP_KERNEL_ACCOUNT);
	if (msg == NULL)
		return NULL;

	msg->next = NULL;
	msg->security = NULL;

	len -= alen;
	pseg = &msg->next;
	while (len > 0) {
		struct msg_msgseg *seg;

		cond_resched();

		alen = min(len, DATALEN_SEG);
		seg = kmalloc(sizeof(*seg) + alen, GFP_KERNEL_ACCOUNT);
		if (seg == NULL)
			goto out_err;
		*pseg = seg;
		seg->next = NULL;
		pseg = &seg->next;
		len -= alen;
	}

	return msg;

out_err:
	free_msg(msg);
	return NULL;
}
~~~
In particular, `m_ts` stores the length of the message. Overwriting it will make the kernel to send back more data to userspace.

At this point, the leak plan is quite obvious. I freed a `chunk` object and then allocated a short `msg_msg` (`next` is `NULL`) to occupy the slot. And then I enlarged its `m_ts` using the UAF-write. Finally, I called `msgrcv` so that data after the `msg_msg` object would be sent back to me in userspace. This gave me a reliable OOB-read primitive.

## Info Leak
Now the question is what to leak.
Since I didn't know many good objects in `kmalloc-128`, I decided to do it in another cache. I went for the classic `struct file` object, which is in `kmalloc-256`.
The idea is quite simple: spray many `struct file` objects so that a new `kmalloc-256` slab full of `struct file` will be allocated right after the target `kmalloc-128` slab. Since I could leak as many bytes as I wanted, I decided to leak two pages to ensure that all content in the next page will be leaked to userspace. Because of how the page allocator works, this spray is actually quite reliable.
~~~
kmalloc-128
xxxx
xxxx <- UAF object
xxxx
kmalloc-256 slab full of struct file
yyyy
yyyy
yyyy
~~~

In memory, a `struct file` object looks like this:
~~~
0xffff96daced9c000:	0x0000000000000000	0x0000000000000000
0xffff96daced9c010:	0xffff96dac110a520	0xffff96dac1b82f00
0xffff96daced9c020:	0xffff96dac1bcd3f8	0xffffffffba229500
0xffff96daced9c030:	0x0000000000000000	0x0000000000000001
0xffff96daced9c040:	0x000a801d00008000	0x0000000000000000
0xffff96daced9c050:	0x0000000000000000	0xffff96daced9c058
0xffff96daced9c060:	0xffff96daced9c058	0x0000000000000000
0xffff96daced9c070:	0x0000000000000000	0x0000000000000000
0xffff96daced9c080:	0x0000000000000000	0x0000000000000000
0xffff96daced9c090:	0xffff96daced5dcc0	0x0000000000000000
0xffff96daced9c0a0:	0x0000000000000000	0x0000000000000000
0xffff96daced9c0b0:	0xffffffffffffffff	0x0000000000000000
0xffff96daced9c0c0:	0xffff96daced852c0	0x0000000000000000
0xffff96daced9c0d0:	0x0000000000000000	0xffff96dac1bcd560
0xffff96daced9c0e0:	0x0000000000000000	0x0000000000000000
0xffff96daced9c0f0:	0x0000000000000000	0x0000000000000000
~~~
This can give us a lot of precious information:
1. kernel base: by leaking `struct file->fops` (`0xffffffffba229500` in the memory dump)
2. UAF object address: `0xffff96daced9c058` points back to itself, which means we can infer the address of the `struct file` object. With a little bit of calculation, we can get the heap address of the UAF object!

This two information is enough for us to fully defeat KASLR.
Now it's time for the fun part.

## arbitrary-free
At this point, overwriting `fops`(which is a pointer to an array of function pointers) would be enough to provide me PC control but I didn't see how.

This is because I totally missed the point that this challenge uses a pretty new kernel and it no longer stores the freelist pointer at the start of the slot. Instead, it stores the freelist pointer in the middle of the slot. Since I missed this point, I thought there was no way to hijack the freelist (the UAF-write starts at offset 0xe and I *thought* the freelist pointer was at offset 0).
It turned out @kileak used this approach and this approach was also the intended approach. A caveat is that this kernel is also compiled with heap cookie, a little bit of calculation is needed to hijack the freelist.

Anyway, I didn't think about hijacking freelist so I came up with another approach: use the arbitrary-free primitive provided by `msg_msg` attack.
Alexander Popov has shown that if the message in `msg_msg` object is too long, the message will be segmented and the unfit part will be stored into a linked list referenced by `next`. Overwriting this `next` pointer provides the attacker arbitrary-free primitive when the kernel tries to clean up the message ([source](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)).

This approach works in long `msg_msg` where `next` is initially not `NULL`. But in my exploit, the `msg_msg` object is very short, and `next` is `NULL`, will the kernel free my faked `next` pointer as well or it will just free my `msg_msg` object? By reading the source code of `free_msg`, it turns out the kernel uses `next` pointer without any checks.
~~~
void free_msg(struct msg_msg *msg)
{
	struct msg_msgseg *seg;

	security_msg_msg_free(msg);

	seg = msg->next;
	kfree(msg);
	while (seg != NULL) {
		struct msg_msgseg *tmp = seg->next;

		cond_resched();
		kfree(seg);
		seg = tmp;
	}
}
~~~
This means overwriting `next` also provides arbitrary-free primitive even in short `msg_msg` object!

## object overlapping
At this point, the most natural thing to do is freeing a `struct file` (the address was leaked already) and then performing a heap spray to overwrite its `fops` pointer.
But somehow I didn't think of it, I went for a weird but easier to implement (and also very interesting) approach: free a misaligned address right before the target `struct file` and reoccupy it with a `chunk` object.

~~~
0xffff96daced9bfc0:	0xf0dcae9bb74c91ea	0x0000000000000000 <- the last slot in kmalloc-128
0xffff96daced9bfd0:	0x0000000000000000	0x0000000000000000
0xffff96daced9bfe0:	0x0000000000000000	0x0000000000000000
0xffff96daced9bff0:	0x0000000000000000	0x0000000000000000 <- what I freed
0xffff96daced9c000:	0x0000000000000000	0x0000000000000000 <- the first slot in kmalloc-256
0xffff96daced9c010:	0xffff96dac110a520	0xffff96dac1b82f00
0xffff96daced9c020:	0xffff96dac1bcd3f8	0xffffffffba229500
0xffff96daced9c030:	0x0000000000000000	0x0000000000000001
0xffff96daced9c040:	0x000a801d00008000	0x0000000000000000
0xffff96daced9c050:	0x0000000000000000	0xffff96daced9c058
0xffff96daced9c060:	0xffff96daced9c058	0x0000000000000000
0xffff96daced9c070:	0x0000000000000000	0x0000000000000000
0xffff96daced9c080:	0x0000000000000000	0x0000000000000000
0xffff96daced9c090:	0xffff96daced5dcc0	0x0000000000000000
0xffff96daced9c0a0:	0x0000000000000000	0x0000000000000000
0xffff96daced9c0b0:	0xffffffffffffffff	0x0000000000000000
0xffff96daced9c0c0:	0xffff96daced852c0	0x0000000000000000
0xffff96daced9c0d0:	0x0000000000000000	0xffff96dac1bcd560
0xffff96daced9c0e0:	0x0000000000000000	0x0000000000000000
0xffff96daced9c0f0:	0x0000000000000000	0x0000000000000000
0xffff96daced9c100:	0x0000000000000000	0x0000000000000000
~~~

In other words, my goal was to overwrite the first `struct file` in `kmalloc-256` (at `0xffff96daced9c000`).
What I did was overwriting the `next` pointer of `msg_msg` to `0xffff96daced9bff0` (`0xffff96daced9c000-0x10`) and then free it.
Interestingly, although it was not a normal slot address, SLUB did not complain about it.
I could reclaim it with `chunk` object and easily overwrite `fops` in `kmalloc-256` using the `edit_storage` function.

## ret2usr
LPE is easy now. It only requires overwriting `fops` to a controlled region and make kernel jump to userspace and execute shellcode there (since SMEP and SMAP are disabled by mistake).

Bypassing SMEP and SMAP is not hard either, it only requires pivoting stack to heap and executing ROP chain there.

# Conclusion
This challenge is not hard. Yet, I still struggled a little bit. Anyway, I like this challenge because I learnt something from it :D

The full exploit can be found [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/vulncon21_ips/exp.c).

# Fun Fact
I was supposed to write this blog a month ago since the exploitation is interesing. But I completely forgot about it because my attention was drawn to kCTF.
Until yesterday, the author of the challenge @BitFriends contacted me, asking about the details of my unintended solution, I was reminded that I still had a blog to finish. And now here it is. Thank you for reminding me @BitFriends and thank you for the challenge!
