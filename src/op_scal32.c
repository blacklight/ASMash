#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_scal32 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];
	u32 scal;

	if (len < 5) return -1;
	get_dstreg(code[0], reg, sizeof(reg), opts);
	memcpy (&scal, code+1, sizeof(scal));

	if ((opts & 0x1) == INTEL_FLAVOR)
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, reg, scal);
	else
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%s\n", op, scal, reg);

	return 0;
}

int op_rotsh (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];

	if (len < 2) return -1;
	get_dstreg(code[1], reg, sizeof(reg), opts);

	if (len == 2)
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s\n", op, reg);
	else if (len == 3)  {
		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, reg, code[2]);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%s\n", op, code[2], reg);
	}

	return 0;
}

