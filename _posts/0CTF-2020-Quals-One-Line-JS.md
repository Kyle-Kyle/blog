---
title: '[0CTF 2020 Quals] - One Line JS'
date: 2020-07-02 21:06:15
tags:
- CTF
- Javascript
- PWN
---

# Introduction
I played 0CTF as a member of Shellphish last weekend. The CTF was pretty awesome and gave me a lot of excitement. I learned about v8 hacking by solving the `Chromium RCE` challenge and about PHP internals by wasting my time on `Baby Bypass`. Overall, I'm pretty satisfied with the experience in the CTF.
The only imperfection is that I didn't manage to pull off `One Line JS` in time before the game ended. In fact, I solved it in 3 hours after the game ended.
`One Line JS` is a very interesting challenge about pwning a small real-world javascript engine. Although it is "small", it still consists of more than 10 thousand lines of code, which is daunting for a 48h CTF. And I guess that's the reason it only got 1 solve during the game.
<!-- more -->
Here, I would like to share how I understood the challenge piece by piece and eventually pwned it in a 24-hour course.
Everything can be found [here](https://github.com/Kyle-Kyle/blog/tree/master/writeups/0ctf20_one_line_js)

# Recon
The target JS engine(`MuJS`) is actually part of `Ghostscript` according to their [website](https://mujs.com/introduction.html). The organizers introduce a backdoor to the project and wante us to pwn it.

`MuJS` is super tiny and it only implements part of javascript features. By playing with the interpreter `mujs` for a bit, I quickly found out that `ArrayBuffer` and `TypedArray` are not implemented. Thankfully, `Array` is still there.

With my previous experience with JS engines, I know that `objects`, `values`, `properties` and `elements` are the most important concepts in exploiting a JS engine(see [\[1\]](http://phrack.org/papers/attacking_javascript_engines.html)). To investigate, I downloaded its source code from [here](https://github.com/ccxvii/mujs) and compiled a debug build to understand how these concepts are implemented in the project.
Indeed, my instinct didn't fail me: there is something fishy here.

The same to other JS engines, `objects` in `mujs` are abstracted by a struct `js_Object`:
~~~
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	int count; /* number of properties, for array sparseness check */
	js_Object *prototype;
	union {
		int boolean;
		double number;
		struct {
			const char *string;
			int length;
		} s;
		...
	} u;
	js_Object *gcnext; /* allocation list */
	js_Object *gcroot; /* scan list */
	int gcmark;
};
~~~
`values` in `mujs` are abstracted by a struct `js_Value`:
~~~
struct js_Value
{
	union {
		int boolean;
		double number;
		char shrstr[8];
		const char *litstr;
		js_String *memstr;
		js_Object *object;
	} u;
	char pad[7]; /* extra storage for shrstr */
	char type; /* type tag and zero terminator for shrstr */
};
~~~
But instead of having a `Shape` or `Map` object to describe how to access an object's properties or elements, it has a `js_Property` object:
~~~
struct js_Property
{
	const char *name;
	js_Property *left, *right;
	int level;
	int atts;
	js_Value value;
	js_Object *getter;
	js_Object *setter;
};
~~~
Basically, a property is a glue connecting `js_Object` and `js_Value`. And `mujs` keeps track of all properties of an object by maintaining a tree. For example, when I try to access `obj.aaa`, the engine will traverse through the property tree and look for a `js_Property` with the `name` `aaa`. If it finds such a `js_Property`, it returns the `js_Value` embeded in the `js_Property`.
By some further investigation, I found out that all the leaves of the property tree are guarded by a statically defined special `js_Property` called `sentinel`.

I got all the results above by examining memory with debug symbols and reading header files. Natually, I tried to do the same for `elements`(elmements in an array). But I found nothing, I was very confused. During the initial exploration, I was sure that `Array` was implemented. So, I took some time to read the C code. it turns out that `elements` are implemented as as `properties`. lol.
~~~
void js_getindex(js_State *J, int idx, int i)
{
	char buf[32];
	js_getproperty(J, idx, js_itoa(buf, i));
}

void js_setindex(js_State *J, int idx, int i)
{
	char buf[32];
	js_setproperty(J, idx, js_itoa(buf, i));
}
~~~

It took me much time to get here, but I got a lot of interesting findings at this point:
1. `ArrayBuffer` and `TypedArray` are not implemented
2. properties are maintained in a tree and `js_Property`-s are scattered in heap
3. there is a pointer in the tree that may help me leak code base(`sentinel`)
4. elements are implemented as properties

# Analysis
Now let's see what changes the organizers did to the project. The patch is actually long. I only show the most important changes here:
~~~
+static void jsB_backdoor(js_State *J)
+{
+	short *s = js_tostring(J, 1);
+	short x = js_toint16(J, 2);
+	if (x > 0x100 && x < 0x1000) {
+		s[x] = x;
+	}
+	js_pushundefined(J);
+}
~~~
~~~
+	js_newcfunction(J, jsB_backdoor, "backdoor", 2);
+	js_setglobal(J, "backdoor");
~~~
Basically, they removed a lot of "insecure" functions to make our life harder and introduced a backdoor which is a limited OOB-write.
Without having information leak, especially with a super dynamic heap(it is deterministic, but the heap layout changes as I change my code), I had to use it smartly.

# OOB-write to type-confusion
A limited OOB-write is far from enough to get a shell. So, how should I use the primitive to gain a better primitive?

My first idea was to overwrite the `size` variable of an `unsortedbin`(a typical heap geek's move) to achieve chunk-overlapping. After this was implemented, I noticed that it was way too unstable. One reason is that the heap layout keeps changing as my code changes. The other reason, also the more important one is that I don't have full control over the heap, any unexpected allocation in the overlapped region may result in a crash.
Once I realized that, I quickly abandoned that idea.

To find what to overwrite, I set breakpoint at the `jsB_backdoor` function and examined the adjacent memory. I noticed that a `js_Value` looks like this in memory:
~~~
0x5555557c3230:	0x00005555557cf4b4	0x0500000000000000
~~~
The first 8 bytes is the data, can be a `double`, can be a `pointer` and even a `char` array. It is followed by 7 bytes of padding and a 1 byte `type` variable. This `type` variable decides how the engine interprets the `js_Value`.

According to the definition:
~~~
enum js_Type {
	JS_TSHRSTR, /* type tag doubles as string zero-terminator */
	JS_TUNDEFINED,
	JS_TNULL,
	JS_TBOOLEAN,
	JS_TNUMBER,
	JS_TLITSTR,
	JS_TMEMSTR,
	JS_TOBJECT,
};
~~~
If I overwrite the `type` variable from 5(`JS_TLITSTR`) to 4(`JS_TNUMBER`), a string pointer will be interpreted as a `double` number. By using this, I was able to leak a heap address.
Naturally, if I overwrite `type` from 4 to 5, a `double` will be interpreted as a pointer and whatever it points to can be returned back to me.
And most importantly, this plan satisfies the constraints of the OOB-write!!!

By summarizing what I had, I came up with a new plan:
1. declare and allocate a string as a reference(in the backdoor function, `obj.toString()` is called, if the type of `obj` is `JS_TLITSTR`, it will directly return its content to me without any transformation)
2. declare an empty object `obj`
3. assign a lot of different string properties to `obj`. This serves as both a spray of `js_Property` and a spray of `js_Value` because each `js_Property` embeds a `js_Value`.
4. use the backdoor to write 0x04xx so the `type` of the `js_Value` will be overwritten by 4.
5. leak heap pointer by traversing the properties of `obj`

It is implemented like this:
~~~
str2='BBBBBBBBBBBBBBBB';
obj={};
for(var i=0;i<0x400;i++) {
	obj["a"+i]="A";
}
offset1 = 1269;
backdoor(str2, offset1);
~~~
The heap layout looks like this:
~~~
str2(the object fed to the backdoor function)
....
....
property1(used for string-to-number)
....
....
property2(used for number-to-string)
....
....
~~~

The plan worked as expected smoothly. At the moment, I was able to get heap address leaked as a double value.

Similarly, after leaking a heap address, I could leak content from any address by reusing the same `obj` object.
1. encode the address in double value
2. assign all its properties to the value
3. use the backdoor to write 0x05xx
4. now the double value is interpreted as a string, so we can leak whatever in that address

In this way, I was supposed to be able to have arbitrary read. Right?

# WTF? Encodings? -> stable arbitrary read
Well, not really.
Now I was able to leak address in two forms:
1. in the string-to-number type confusion, leak addresses in double values
2. in the number-to-string type confusion, leak addresses by dereferencing a controlled pointer

Sounds like a plan.
But, how to transform a double value to an integer so arithmetic operations can be performed on the pointer? Easy, by using `ArrayBuffer` and `TypedArray`... Oh wait, they are not implemented. WTF?
This got me stuck for a while until I found a [super old snippet](https://stackoverflow.com/questions/25942516/double-to-byte-array-conversion-in-javascript) that supports this by pure javascript calculations. It is not perfect, but it works most of the time.

OK, problem 1 solved. What's wrong with directly printing strings?
The problem is: `mujs` stores strings in utf-8 encoding. When it encounters an invalid utf-8 character in a string, it gets confused and returns a bad character to us. For example, `s = "\xd0"` will store `\xc3\x90` in memory. When we do `s[0]`, it returns `\xd0` correctly. However, in our exploitation, if what we want to leak has `\xd0` as the first byte, `s[0]` returns a bad character because `\xd0` is not a valid utf-8 encoding.
I thought this was inevitable, there was no way to retore the address perfectly for some time. But at one point, I realized it may be possible to transform the bad characters into some other forms first and then transform it back to integers. Indeed, it worked. And the magic function is `encodeURI`.
By using the arbitrary read, it's easy to leak the code base by traversing a property tree to find the `sentinel` leaf. Then libc can be leaked easily.

# addrof and ... wait a second
In modern JS engine exploitations, there are two very important primitives: `addrof` and `fakeobj`.
`addrof`: give it an object, the primitive is able to tell the address of the object.
`fakeobj`: prepare payload in memory and give it the payload address, the primitive is able to make the JS engine think the payload is a valid object.
By chaining these two primitives, an attacker can easily gain arbitrary read/write primitive.

In fact, I have already implemented the `addrof` primitive by the string-to-number type confusion. Instead of giving it a string, giving it any object and then overwrite its type to 4 can leak the address of the object.
`addrof` is done. Good.

I encountered issues when trying to implement `fakeobj`. To implement `fakeobj`, there are two steps:
1. prepare payload(a fake object) in memory
2. type confusion from number to object

Step2 is easy in our case. What about step1?
Step1 is also easy in most JS engines because of the existence of `ArrayBuffer` and the fact that properties are usually stored linearly. But in `mujs`, `ArrayBuffer` is not implemented. And properties are scattered. How to prepare a fake object in `mujs` then?
In fact, I didn't manage to find a method to make attacker controlled data stored linearly in memory after arbitray read. Instead, I tried to reuse what I had in hand.

# fakestr and arbitrary write
Recall what I have achieved: string-to-number becomes `addrof` primitive, what about number-to-string?
It is still `fakeobj` in a sense, because it gives me a fake string. And it is possible to access it in the JS binding.
Now, what if I use the fake string as the argument to the backdoor function? Since the internal pointer of the string is provided by me, I could write to anywhere I want 2 bytes at a time. That's a limited arbitrary write primitive!

# Arbitrary read/write and RCE
At this moment, I got arbitray read/write. Although I could only write 2 bytes at a time, it should be enough to get shell in many ways.
My approach was:
1. prepare a `js_Property` around `__free_hook` by copy & pasting a real property. where `__free_hook` corresponds to the data of the `js_Value`
2. hijack a property pointer to our fake property
3. overwrite `__free_hook` by setting the property with `system`(encoded in double)
4. trigger `free(cmd)`

(When I'm writing this, I just realize hijacking an empty tcache free list is a better way... One thing worth noticing, we can't overwrite tcachebin in the metadata because of the nature of the backdoor: the reference object will points to an unmaped region and crashes.)

# Finish
The CTF ended right after I got `system` execution. It was not too close though. It still took me 10-20 minutes to trigger my command stably.
Most importantly... this challenge requires the attack script in one line and the max length is 4096. But when it worked for the first time, it had more than 10000 characters... It took me almost 2 hours to shrink it to around 3500(I made a mistake so I thought the limit was 3200....).
Final exploit is [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/0ctf20_one_line_js/pwn.js)
A working and also relatively readable exploit is [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/0ctf20_one_line_js/work_readable.js)
Yet another relatively readable exploit is [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/0ctf20_one_line_js/leak_readable.js)

# Conclusion
This challenge is all about adapting previous knowledge into a new target. We need to understand the difference between the new target and what we've encountered before first. And then we should try to apply what we knew if there are anything similar.
Most importantly, we need to try to get out of the comfort zone and take new challenges. This is the best why to learn and gain better understanding of what we already know.

