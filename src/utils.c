#include <stdio.h>
#include <memory.h>
#include "elfshark.h"

void get_srcreg (u8 code, char srcreg[], u8 len, u8 opts)  {
	switch ((code & 0x38) >> 3)  {
		case EAX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "eax");
			else snprintf (srcreg, len, "%%eax");
			break;

		case ECX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ecx");
			else snprintf (srcreg, len, "%%ecx");
			break;

		case EDX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "edx");
			else snprintf (srcreg, len, "%%edx");
			break;

		case EBX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ebx");
			else snprintf (srcreg, len, "%%ebx");
			break;

		case ESP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "esp");
			else snprintf (srcreg, len, "%%esp");
			break;

		case EBP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ebp");
			else snprintf (srcreg, len, "%%ebp");
			break;

		case ESI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "esi");
			else snprintf (srcreg, len, "%%esi");
			break;

		case EDI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "edi");
			else snprintf (srcreg, len, "%%edi");
			break;
	}
}

void get_dstreg (u8 code, char dstreg[], u8 len, u8 opts)  {
	switch (code & 0x07)  {
		case EAX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "eax");
			else snprintf (dstreg, len, "%%eax");
			break;

		case ECX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ecx");
			else snprintf (dstreg, len, "%%ecx");
			break;

		case EDX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "edx");
			else snprintf (dstreg, len, "%%edx");
			break;

		case EBX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ebx");
			else snprintf (dstreg, len, "%%ebx");
			break;

		case ESP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "esp");
			else snprintf (dstreg, len, "%%esp");
			break;

		case EBP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ebp");
			else snprintf (dstreg, len, "%%ebp");
			break;

		case ESI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "esi");
			else snprintf (dstreg, len, "%%esi");
			break;

		case EDI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "edi");
			else snprintf (dstreg, len, "%%edi");
			break;
	}
}

void get_srcreg16 (u8 code, char srcreg[], u8 len, u8 opts)  {
	switch ((code & 0x38) >> 3)  {
		case AX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ax");
			else snprintf (srcreg, len, "%%ax");
			break;

		case CX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "cx");
			else snprintf (srcreg, len, "%%cx");
			break;

		case DX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "dx");
			else snprintf (srcreg, len, "%%dx");
			break;

		case BX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "bx");
			else snprintf (srcreg, len, "%%bx");
			break;

		case SP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "sp");
			else snprintf (srcreg, len, "%%sp");
			break;

		case BP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "bp");
			else snprintf (srcreg, len, "%%bp");
			break;

		case SI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "si");
			else snprintf (srcreg, len, "%%si");
			break;

		case DI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "di");
			else snprintf (srcreg, len, "%%di");
			break;
	}
}

void get_dstreg8 (u8 code, char dstreg[], u8 len, u8 opts)  {
	switch (code & 0x07)  {
		case AL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "al");
			else snprintf (dstreg, len, "%%al");
			break;

		case CL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "cl");
			else snprintf (dstreg, len, "%%cl");
			break;

		case DL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "dl");
			else snprintf (dstreg, len, "%%dl");
			break;

		case BL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "bl");
			else snprintf (dstreg, len, "%%bl");
			break;

		case AH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ah");
			else snprintf (dstreg, len, "%%ah");
			break;

		case CH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ch");
			else snprintf (dstreg, len, "%%ch");
			break;

		case DH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "dh");
			else snprintf (dstreg, len, "%%dh");
			break;

		case BH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "bh");
			else snprintf (dstreg, len, "%%bh");
			break;
	}
}


void get_dstreg16 (u8 code, char dstreg[], u8 len, u8 opts)  {
	switch (code & 0x07)  {
		case AX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "ax");
			else snprintf (dstreg, len, "%%ax");
			break;

		case CX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "cx");
			else snprintf (dstreg, len, "%%cx");
			break;

		case DX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "dx");
			else snprintf (dstreg, len, "%%dx");
			break;

		case BX:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "bx");
			else snprintf (dstreg, len, "%%bx");
			break;

		case SP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "sp");
			else snprintf (dstreg, len, "%%sp");
			break;

		case BP:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "bp");
			else snprintf (dstreg, len, "%%bp");
			break;

		case SI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "si");
			else snprintf (dstreg, len, "%%si");
			break;

		case DI:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (dstreg, sizeof(dstreg), "di");
			else snprintf (dstreg, len, "%%di");
			break;
	}
}

void get_srcreg8 (u8 code, char srcreg[], u8 len, u8 opts)  {
	switch ((code & 0x38) >> 3)  {
		case AL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "al");
			else snprintf (srcreg, len, "%%al");
			break;

		case CL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "cl");
			else snprintf (srcreg, len, "%%cl");
			break;

		case DL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "dl");
			else snprintf (srcreg, len, "%%dl");
			break;

		case BL:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "bl");
			else snprintf (srcreg, len, "%%bl");
			break;

		case AH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ah");
			else snprintf (srcreg, len, "%%ah");
			break;

		case CH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "ch");
			else snprintf (srcreg, len, "%%ch");
			break;

		case DH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "dh");
			else snprintf (srcreg, len, "%%dh");
			break;

		case BH:
			if ((opts & 0x1) == INTEL_FLAVOR) snprintf (srcreg, sizeof(srcreg), "bh");
			else snprintf (srcreg, len, "%%bh");
			break;
	}
}


int interrupt (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	if (len < 2) return -1;

	if ((opts & 0x1) == INTEL_FLAVOR) snprintf (buf, buflen, "int\t%xh\n", code[1]);
	else snprintf (buf, buflen, "int\t$0x%x\n", code[1]);
	return 0;
}

int op_inout (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	u8 op, off_index;

	if (opts & BITS_16)  {
		if (code[0] != 0x66 && len < 2) return -1;
		op = code[1];
		off_index = 2;
	} else {
		if (len < 1) return -1;
		op = code[0];
		off_index = 1;
	}

	switch (op)  {
		case 0xe4:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "in\tal,0x%x\n", code[off_index]);
			else
				snprintf (buf, buflen, "in\t$0x%x,%%al\n", code[off_index]);
			break;

		case 0xe5:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "in\t%s,0x%x\n",
						(opts & BITS_16) ? "ax" : "eax", code[off_index]);
			else
				snprintf (buf, buflen, "in\t$0x%x,%s\n",
						code[off_index], (opts & BITS_16) ? "%%ax" : "%%eax");
			break;

		case 0xe6:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "out\t0x%x,al\n", code[off_index]);
			else
				snprintf (buf, buflen, "out\t%%al,$0x%x\n", code[off_index]);
			break;

		case 0xe7:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "out\t0x%x,%s\n",
						code[off_index], (opts & BITS_16) ? "ax" : "eax");
			else
				snprintf (buf, buflen, "out\t%s,$0x%x\n",
						(opts & BITS_16) ? "%%ax" : "%%eax", code[off_index]);
			break;

		case 0xec:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "in\tal,dx\n");
			else
				snprintf (buf, buflen, "in\t(%%dx),%%al\n");
			break;

		case 0xed:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "in\t%s,dx\n",
						(opts & BITS_16) ? "ax" : "eax");
			else
				snprintf (buf, buflen, "in\t(%%dx),%s\n",
						(opts & BITS_16) ? "%%ax" : "%%eax");
			break;

		case 0xee:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "out\tdx,al\n");
			else
				snprintf (buf, buflen, "out\t(%%al),%%dx\n");
			break;

		case 0xef:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf, buflen, "out\tdx,%s\n",
						(opts & BITS_16) ? "ax" : "eax");
			else
				snprintf (buf, buflen, "out\t(%s),%%dx\n",
						(opts & BITS_16) ? "%%ax" : "%%eax");
			break;
	}

	return 0;
}

void unknown (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	int i;
	memset (buf, 0x0, buflen);

	for (i=0; i<len; i++)
		sprintf (buf, "%s.byte\t%.2x\n", buf, code[i]);
}

