---
title: '[DEFCON 2021 Quals] - mooosl'
date: 2021-05-08 16:20:15
tags:
- CTF
- heap
- musl
- PWN
---

# Introduction
Last week, I played DEFCON quals with my team Shellphish. We managed to get to 10th place worldwide and qualified for DEFCON Final this year. Good job everyone! More importantly, this is the 16th year that Shellphish gets qualified for DEFCON Final consecutively in a row. What can I say? It's just amazing.
During the CTF, I contributed to the solution of `baby-a-fallen-lap-ray`(or, `parallel-af-yan`). After we solved it, I started looking at `mooosl`, which is a heap challenge with musl[1] libc. When I started to look at the challenge seriously, there were only 6 hours left. At the end of the CTF, I almost got everything, just needed some time to finish it off.
In fact, after the CTF, it only took me 2.5 more hours to finally get the flag. So sad.
So, in this blog, I'm going to talk about how to solve the challenge and help myself remember how `musl`'s `mallocng` allocator works.

<!-- more -->

# Challenge
This challenge is a menu-based challenge, in the typical heap challenge style. It implements a key-value storage service. User can input key/value pairs and then later query/delete the values using the keys.
A store entry is defined as follow:
~~~
struct store_t {
	void *key;
	void *value;
	ulong key_len;
	ulong val_len;
	ulong hash;
	struct store_t *next;
}
~~~
One thing worth noticing, `key_len` and `val_len` are in our control. The program allocates `key_len` bytes and stores the returned pointer into `key`. It does the same to `value` and `val_len`.

The program implements a standard hash table, the `key` will be hashed into `hash`. And the last 12bit of hash(or `hash` % 0x1000) will be used to decide the bucket in the hash table. `store`-s in the same bucket will be linked into a singly linked list.

The vulnerability is very straightforward, when the last `store` in a bucket list is deleted, it frees `key`, `hash` and itself. However, the `store` before the item still has a reference to the freed `store`, leading to UAF vulnerability.

In other words, if we allocate two `store`-s, `a` and `b`, the list will be `b->a->NULL`. After `a` is deleted, `b` does not clear the reference to `a`, the list is still `b->a->NULL`. But now, `a` is freed, which means we can fake `store` items in the list.

# mallocng
To exploit it, we need to understand how the musl libc's allocator works.
The first thing can be easily observed is that this allocator does not follow the last-in-first-out principal. This makes exploiting the UAF vulnerablitliy a non-trivial task.

### slot
By reading the source code and inspecting the memory, we found out that the atomic structure in `mallocng` is called `slot`.
It looks like this in memory:
![slot](https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/defcon_qual21/slot.png)
The first 0x10 bytes is the encoded metadata of the `slot`, after that, everything belongs to users. In the metadata, only two bytes are important for us: 0x08(`p[-2]`) and 0xa2(`p[-3]`) in the picture above.
`p[-2]` represents `offset`, `p[-3] & 31` represents `index`.

### group
A `group` consists of several `slots` of the same size. A `group` looks like this in memory:
![group](https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/defcon_qual21/group.png)
The metadata of the first `slot` in a `group` contains a pointer pointing to the real metadata of this `group`. Other `slot`-s use their `offset` to recover the metadata pointer to access the metadata of the `group`. It is done through the formula `p-offset*UNIT` where `UNIT` is fixed to be 0x10. The `index` of a `slot` represents its position in the `group`. In other words, a `slot` can be precisely represented by a `(group, index)` tuple.

### meta
Now let's have a look at the `group` metadata. It looks like this in memory:
![meta](https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/defcon_qual21/meta.png)
It uses `mem` to keep track of the location of the `group` and uses `sizeclass` to keep track of the size of the `slot` in the `group`. `freed_mask` and `avail_mask` are bitmaps of freed `slots` and availble but haven't been allocated yet `slots` respectively.

### meta_area
Interestingly, to make sure every `meta` struct in use is valid and not crafted by attackers, `mallocng` implements a verification mechanism that ensures the `meta` struct is at an protected `meta_area`.
`meta_area` looks like this in memory:
![meta](https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/defcon_qual21/meta_area.png)
Whenever a `meta` struct is used, it clears the last 12 bits of its pointer to recover its `meta_area` and ensure the `check` value is the same as the initialized random value.

### __malloc_context
To keep track of the runtime information, `mallocng` uses a global variable `__malloc_context` to keep track of a list of active `groups`.

### malloc
When `malloc` is invoked, `mallocng` translate the number of bytes to `sizeclass` and allocates a `slot` from the active `group` in `__malloc_context` corresponding to the `sizeclass` and then encode the `offset` and `index` info in the beginning of the `slot`.

### free
When `free` is called, the allocator uses `offset` to recover the `meta` struct and then flips the `index`-th bit in its `freed_mask`. It also destroys the `slot`'s `offset` by rewriting it to `0xff` to prevent double free.

# Exploitation
Now we understand how `mallocng` works, we can dive into the exploitation.

### Initial Info Leak
The first thing to do is to leak information, specifically, libc base.
This can be easily done through the UAF. Remember we have a listed list `b->a->NULL` where `a` and its `key` and `content` are freed. And whenever we do a query, the program traverses the list to find matching `store`. What we can do is:
1. do not overwrite `a` which is a `store` struct and its `key`
2. allocate another `store` struct called `c` and make it overlap with `a`'s `content`
3. do a query on `a`

By doing this, the program will traverse the list and print out `a`'s content, which is `c`'s `key` pinter to us. This is how we reveal the location of heap.

### Arbitrary Leak and Free
With known heap address, we can now overwrite `a` with a `content` and make its `key` pointing to something we know so we can query it later. At the same time, we overwrite its `content` with wherever we want to leak. So, when we query this `store`(at `a`'s location with a known key), we can get arbitrary leak through its `content`.

Under the same setting, if we free the `store` whose `content` is in our control, we basically can call `free` on arbitrary location.

### Arbitrary Allocation
Now here comes the tricky part: how to obtain arbitrary allocation when there is virtually no pointer on heap(we can't overwrite the meta pointer because of security checks)?

Initially, I thought about overwriting the `mem` pointer of a `meta` struct. Since `mem` is how `meta` keeps track of where the `group` is, if we overwrite that, we can allocate to where `mem` points to. However, the only way I could think of is to use the unlink logic in `delete` function. That means `mem` points to a valid `store` struct. But `mem` points to `group` and the first attribute of `group` is `meta` pointer. When the `store` is freed, the first attribute(`key`) will be freed. That means, `meta` is free-able, which is impossible. So, I gave up this plan eventually.

Stuck here for a while, I finally came up with what we can do after reading a lot of the source code: we can forge a `meta` and inject it into `__malloc_context`. The injection logic is in `nontrivial_free` function. It somehow adds a `meta` into `__malloc_context` if the `meta` struct satisfies some conditions.

To successfully forge a `meta`, we actually need to do a lot:
1. forge a `meta` struct and `meta_area`. This can be done by allocting two pages and use the second page as the `meta_area`. We use the second page because we don't control the start of the first page, which is resevered for `slot` metadata. And ofc, don't forget to fill in the `check` value in the `meta_area`
2. forge a `group` by forging a `slot` with `0` as the `offset` and `index`. We also fill its first 8 bytes with the pointer pointing to our faked `meta` struct.
3. use the arbitrary free to free our faked `slot`

Now, a faked `meta`(or say a faked `group`) is injected into `__malloc_context`, we can get arbitrary allocation using `malloc`.

### Fix calloc
However, the challenge program uses `calloc`, which clears the `slot` after `malloc`. By default, it uses a nontrivial algorithm to clear the region. It needs to use the encoded metadata to recover `meta` in the allocated region. But in our exploitation, the allocated region will be something like stack, there is no way it has valid encoded metadata.

Thankfully, in the implementation of `calloc`, if a global variable `__malloc_replaced` is set, it will skip the nontrivial `__malloc_allzerop` logic and directly use `memset` to clear the `slot`.

~~~
void *calloc(size_t m, size_t n)
{
	if (n && m > (size_t)-1/n) {
		errno = ENOMEM;
		return 0;
	}
	n *= m;
	void *p = malloc(n);
	if (!p || (!__malloc_replaced && __malloc_allzerop(p)))
		return p;
	n = mal0_clear(p, n);
	return memset(p, 0, n);
}
~~~

What we can do is to use the arbitrary allocation primitive to allocate a `slot` near `__malloc_replaced` and use the encoded metadata to make `__malloc_replaced` nonzero.

After that, we can perform arbitrary allocation using `calloc`.

### Get Shell
The hard part is done. With the arbitrary allocation, we can overwrite return address on stack and get shell.
However, I offer another solution here: we can use FSOP in musl.
The `FILE` struct in `musl` is similar to that in `glibc`. The difference is that `musl` does not use vtable, it keeps the pointers in the data structure.
What we can do is to use the arbitrary allocation to overwrite its `write` pointer with `system` and replace its `flag` with `E;sh;\x00`. When `puts` is called, the `write` function will be called with its `flag` as the first argument. After the overwite, it becomes `system("E;sh;\x00")` and gives us a shell.
("E;" is here because the original flag is 0x45("E"), I want to preserve the `flag`)

# Conclusion
I had fun with the challenge. Although I didn't solve it in time. If only I didn't sleep 7 hours straight after solving `parallel-af-yan`. So sad.
It and also tells me why comment is important in programming. The `mallocng` source code is very badly commented, which caused a lot of troubles for me to understand how it works.

The full script can be found [here](https://github.com/Kyle-Kyle/blog/tree/master/writeups/defcon21_mooosl)

# Reference
[1] https://www.musl-libc.org/
