#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_scal81 (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];
	char op[8];
	u32 scal;

	if (len < 6) return -1;
	get_dstreg(code[0], reg, sizeof(reg), opts);

	memcpy (&scal, code+2, sizeof(scal));
	memset (op, 0x0, sizeof(op));

	switch ((code[1] & 0xf8) >> 3)  {
		case 0x18: strcpy (op, "add"); break;
		case 0x19: strcpy (op, "or" ); break;
		case 0x1a: strcpy (op, "adc"); break;
		case 0x1b: strcpy (op, "sbb"); break;
		case 0x1c: strcpy (op, "and"); break;
		case 0x1d: strcpy (op, "sub"); break;
		case 0x1e: strcpy (op, "xor"); break;
		case 0x1f: strcpy (op, "cmp"); break;
	}

	if ((opts & 0x1) == INTEL_FLAVOR)
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, reg, scal);
	else
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%s\n", op, scal, reg);

	return 0;
}

int op_scal83 (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];
	char op[8];
	u8   scal;

	if (len < 3) return -1;
	get_dstreg(code[1], reg, sizeof(reg), opts);

	scal = code[2];
	memset (op, 0x0, sizeof(op));

	switch ((code[1] & 0xf8) >> 3)  {
		case 0x18: strcpy (op, "add"); break;
		case 0x19: strcpy (op, "or" ); break;
		case 0x1a: strcpy (op, "adc"); break;
		case 0x1b: strcpy (op, "sbb"); break;
		case 0x1c: strcpy (op, "and"); break;
		case 0x1d: strcpy (op, "sub"); break;
		case 0x1e: strcpy (op, "xor"); break;
		case 0x1f: strcpy (op, "cmp"); break;
	}

	if ((opts & 0x1) == INTEL_FLAVOR)
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, reg, scal);
	else
		snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%s\n", op, scal, reg);

	return 0;
}

