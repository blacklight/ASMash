#include <stdio.h>
#include <string.h>
#include "elfshark.h"

void single_op (u8 code, char buf[], u8 buflen, u8 opts)  {
	char reg[8];
	get_dstreg(code, reg, sizeof(reg), opts);

	switch (code)  {
		case 0x27:
			sprintf (buf+strlen(buf), "daa\n"); break;
		case 0x2f:
			sprintf (buf+strlen(buf), "das\n"); break;
		case 0x37:
			sprintf (buf+strlen(buf), "aaa\n"); break;
		case 0x60:
			sprintf (buf+strlen(buf), "pusha\n"); break;
		case 0x61:
			sprintf (buf+strlen(buf), "popa\n"); break;
		case 0x90:
			sprintf (buf+strlen(buf), "nop\n"); break;

		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
			sprintf (buf+strlen(buf), "xchg\t%s,%s\n",
					((opts & 0x1) == INTEL_FLAVOUR) ? "eax" : "%%eax", reg); break;

		case 0x98:
			sprintf (buf+strlen(buf), "cwtl\n"); break;
		case 0x99:
			sprintf (buf+strlen(buf), "cltd\n"); break;
		case 0x9b:
			sprintf (buf+strlen(buf), "fwait\n"); break;
		case 0x9c:
			sprintf (buf+strlen(buf), "pushf\n"); break;
		case 0x9d:
			sprintf (buf+strlen(buf), "popf\n"); break;
		case 0x9e:
			sprintf (buf+strlen(buf), "sahf\n"); break;
		case 0x9f:
			sprintf (buf+strlen(buf), "lahf\n"); break;
		case 0xc3:
			sprintf (buf+strlen(buf), "ret\n"); break;
		case 0xc9:
			sprintf (buf+strlen(buf), "leave\n"); break;
		case 0xcb:
			sprintf (buf+strlen(buf), "retf\n"); break;
		case 0xce:
			sprintf (buf+strlen(buf), "into\n"); break;
		case 0xcf:
			sprintf (buf+strlen(buf), "iret\n"); break;
		case 0xf4:
			sprintf (buf+strlen(buf), "hlt\n"); break;
		case 0xf5:
			sprintf (buf+strlen(buf), "cmc\n"); break;
		case 0xf8:
			sprintf (buf+strlen(buf), "clc\n"); break;
		case 0xf9:
			sprintf (buf+strlen(buf), "stc\n"); break;
		case 0xfa:
			sprintf (buf+strlen(buf), "cli\n"); break;
		case 0xfb:
			sprintf (buf+strlen(buf), "sti\n"); break;
		case 0xfc:
			sprintf (buf+strlen(buf), "cld\n"); break;
		case 0xfd:
			sprintf (buf+strlen(buf), "std\n"); break;
	}
}

