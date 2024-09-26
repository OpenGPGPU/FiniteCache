#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "echodev-cmd.h"

int main(int argc, char **argv)
{
	int fd, status;
	uint32_t value;
	struct kern_ring kern_args;
	uint64_t *kern_ringbuffer;
	uint8_t *kerns[64];

	kerns[0] = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	kerns[1] = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	kern_args.size = 127;
	kern_args.rptr = 0;
	kern_args.wptr = 0;


	kerns[0][1] = 11;
	kerns[1][2] = 22;
	if(argc != 3 && argc != 4) {
		printf("Usage: %s <devfile> <cmd> [<arg>]\n", argv[0]);
		return 0;
	}

	fd = open(argv[1], O_RDWR);
	if(fd < 0) {
		perror("open");
		return fd;
	}
	kern_ringbuffer = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (kern_ringbuffer == MAP_FAILED) {
		perror("mmap\n");
		close(fd);
		return 0;
	}

	kern_ringbuffer[0] = kerns[0];
	kern_ringbuffer[1] = kerns[1];
	printf("cpu data is %d %d %d %d\n", kerns[0][0], kerns[0][1], kerns[0][2], kerns[0][3]);
	if(strcmp(argv[2], "GET_ID") == 0) {
		status = ioctl(fd, GET_ID, &value);
		printf("ioctl returned %d, ID Register: 0x%x\n", status, value);
	} else if(strcmp(argv[2], "GET_INV") == 0) {
		status = ioctl(fd, GET_INV, &value);
		printf("ioctl returned %d, Inverse Pattern Register: 0x%x\n", status, value);
	} else if(strcmp(argv[2], "GET_RAND") == 0) {
		status = ioctl(fd, GET_RAND, &value);
		printf("ioctl returned %d, Random Value Register: 0x%x\n", status, value);
	} else if (strcmp(argv[2], "SET_INV") == 0) {
		value = strtoll(argv[3], 0, 0);
		status = ioctl(fd, SET_INV, &value);
		printf("ioctl returned %d\n", status);
	} else if(strcmp(argv[2], "IRQ") == 0) {
		status = ioctl(fd, IRQ, NULL);
		printf("ioctl returned %d, IRQ was triggered\n", status);
	} else if(strcmp(argv[2], "KERN_RING") == 0) {
		status = ioctl(fd, KERN_RING, &kern_args);
	} else if(strcmp(argv[2], "KERN_WPTR") == 0) {
		value = strtoll(argv[3], 0, 0);
		status = ioctl(fd, KERN_WPTR, &value);
	} else {
		printf("%s is not a valid cmd\n", argv[2]);
	}

	printf("kern0 va %p\n", kerns[0]);
	printf("sleep ...\n");
	sleep(2); // after kernel launch
	printf("gpu compute result is %d %d %d %d\n", kerns[0][0], kerns[0][1], kerns[0][2], kerns[0][3]);
	close(fd);
	return 0;
}
