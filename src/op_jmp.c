#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_jmp (char* op, u8 code[], u8 len, char buf[], u8 buflen, u32 addr, u8 opts)  {
	int  pos_off;
	char neg_off;

	if (len < 2) return -1;

	if (len == 5)  { 
		memcpy (&pos_off, code+1, sizeof(pos_off));

		if ((opts & 0x1) == INTEL_FLAVOUR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%xh\n",  op, (addr + pos_off));
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t0x%x\n", op, (addr + pos_off));
	}

	if (len == 2)  {
		neg_off = code[1];
		memcpy (&neg_off, code+1, sizeof(neg_off));

		if ((opts & 0x1) == INTEL_FLAVOUR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%xh\n",  op, (addr + neg_off));
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t0x%x\n", op, (addr + neg_off));
	}
}

int op_jmp_ff (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char dstreg[8];

	if (len < 2) return -1;

	get_dstreg(code[1], dstreg, sizeof(dstreg), opts);

	switch ((code[1] & 0xc0) >> 6)  {
		case 0x00:
			if ((opts & 0x1) == INTEL_FLAVOUR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t[%s]\n", op, dstreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,*(%s)\n", op, dstreg);
			break;

		case 0x01:
			if (len < 3) return -1;

			if ((opts & 0x1) == INTEL_FLAVOUR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t[%s+%d]\n", op, dstreg, code[2]);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,*0x%x(%s)\n", op, code[2], dstreg);
			break;

		case 0x03:
			if ((opts & 0x1) == INTEL_FLAVOUR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s\n", op, dstreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,*%s\n", op, dstreg);
			break;
	}
}

