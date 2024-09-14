#ifndef ECHODEV_CMD_H
#define ECHODEV_CMD_H

#define GET_ID 0x00
#define GET_RAND 0x20
#define GET_INV 0x30
#define SET_INV 0x40
#define IRQ 0x50
#define KERN_RING 0x60
#define KERN_WPTR 0x61


struct kern_ring {
	uint64_t base;
	uint32_t size;
	uint32_t rptr;
	uint32_t wptr;
};

#endif
