#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_reg32 (char* op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char srcreg[8], dstreg[8];
	u32 offset;

	if (len < 2) return -1;

	if (opts & BITS_16)  {
		( ((code[2] & 0x07) == 0) || ((code[2] & 0x07) == 1) )
			? get_dstreg(code[1], dstreg, sizeof(dstreg), opts)
			: get_dstreg16(code[1], dstreg, sizeof(dstreg), opts);

		get_srcreg16(code[1], srcreg, sizeof(srcreg), opts);
	} else if (opts & BITS_8)  {
		( ((code[2] & 0x07) == 0) || ((code[2] & 0x07) == 1) )
			? get_dstreg(code[1], dstreg, sizeof(dstreg), opts)
			: get_dstreg8(code[1], dstreg, sizeof(dstreg), opts);

		get_srcreg8(code[1], srcreg, sizeof(srcreg), opts);
	} else {
		get_srcreg(code[1], srcreg, sizeof(srcreg), opts);
		get_dstreg(code[1], dstreg, sizeof(dstreg), opts);
	}

	if ( ((code[0] & 0xfc) >> 2) == 0x28)  {
		memcpy (&offset, code+1, sizeof(offset));

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\tDWORD PTR 0x%x,eax\n", op, offset);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%%eax\n", op, offset);

		return 0;
	}

	if (code[0] == 0x25)  {
		memcpy (&offset, code+1, sizeof(offset));

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\teax,0x%x\n", "and", offset);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%%eax\n", "and", offset);

		return 0;
	}

	if ((code[1] & 0x7) == 0x5 && code[1] < 0x40)  {
		if (len < 6) return -1;

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\tDWORD PTR 0x%x,%s\n", op, offset, srcreg);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, srcreg, offset);

		return 0;
	}

	switch ((code[1] & 0xc0) >> 6)  {
		case 0x0:
			if ((code[1] & 0x07) == EBP)  {
				unknown (code, len, buf, buflen, opts);
				break;
			}

			if ((code[1] & 0x07) == ESP)  {
				if (len < 3 || code[2] != 0x24)  {
					unknown (code, len, buf, buflen, opts);
					break;
				}
			}

			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t[%s],%s\n", op, dstreg, srcreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,(%s)\n", op, srcreg, dstreg);
			break;

		case 0x1:
			if (len < 3)  {
				unknown (code, len, buf, buflen, opts);
				break;
			}

			offset = code[2];

			if ((code[1] & 0x07) == ESP)  {
				if (len < 4 || code[2] != 0x24)  {
					unknown (code, len, buf, buflen, opts);
					break;
				}

				offset = code[3];
			}

			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t[%s+%d],%s\n", op, dstreg, offset, srcreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x(%s)\n", op, srcreg, offset, dstreg);
			break;

		case 0x2:
			unknown (code, len, buf, buflen, opts);
			break;

		case 0x3:
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,%s\n", op, dstreg, srcreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,%s\n", op, srcreg, dstreg);
			break;
	}

	return 0;
}

int op_reg32_inv (char* op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char srcreg[8], dstreg[8];
	u32 offset;

	if (len < 2) return -1;
	if (code[1] >= 0x80) return -1;

	if (opts & BITS_16)  {
		( ((code[2] & 0x07) == 0) || ((code[2] & 0x07) == 1) )
			? get_srcreg(code[1], srcreg, sizeof(srcreg), opts)
			: get_srcreg16(code[1], srcreg, sizeof(srcreg), opts);

		get_dstreg16(code[2], dstreg, sizeof(dstreg), opts);
	} else {
		get_srcreg(code[1], srcreg, sizeof(srcreg), opts);
		get_dstreg(code[1], dstreg, sizeof(dstreg), opts);
	}

	if ((code[1] & 0x7) == 0x5)  {
		if (len < 6) return -1;

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,DWORD PTR 0x%x\n", op, srcreg, offset);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t0x%x,%s\n", op, offset, srcreg);

		return 0;
	}

	switch ((code[1] & 0x40) >> 6)  {
		case 0x0:
			if ((code[1] & 0x07) == EBP)  {
				unknown (code, len, buf, buflen, opts);
				break;
			}

			if ((code[1] & 0x07) == ESP)  {
				if (len < 3 || code[2] != 0x24)  {
					unknown (code, len, buf, buflen, opts);
					break;
				}
			}

			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,[%s]\n", op, dstreg, srcreg);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t(%s),%s\n", op, srcreg, dstreg);
			break;

		case 0x1:
			if (len < 3)  {
				unknown (code, len, buf, buflen, opts);
				break;
			}

			offset = code[2];

			if ((code[1] & 0x07) == ESP)  {
				if (len < 4 || code[2] != 0x24)  {
					unknown (code, len, buf, buflen, opts);
					break;
				}

				offset = code[3];
			}

			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,[%s+%d]\n", op, dstreg, srcreg, offset);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t0x%x(%s),%s\n", op, offset, srcreg, dstreg);
			break;
	}

	return 0;
}

void op_incdec (u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];
	u8 op;

	op = ((opts & BITS_16) || (opts & BITS_8)) ? code[1] : code[0];

	if (opts & BITS_16)
		get_dstreg16 (op, reg, sizeof(reg), opts);
	else if (opts & BITS_8)
		get_dstreg8  (op, reg, sizeof(reg), opts);
	else
		get_dstreg   (op, reg, sizeof(reg), opts);

	snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s\n",
			((op & 0x08) >> 3) ? "dec" : "inc", reg);
}

int op_lea32 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char srcreg[8], dstreg[8];

	if (len < 2) return -1;

	get_srcreg (code[1], srcreg, sizeof(srcreg), opts);

	if (opts & BITS_16)
		get_dstreg16 (code[1], dstreg, sizeof(dstreg), opts);
	else
		get_dstreg (code[1], dstreg, sizeof(dstreg), opts);

	if ((code[1] & 0xc0) == 0x00)  {
		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,[%s]\n", op, dstreg, srcreg);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t(%s),%s\n", op, srcreg, dstreg);
	} else if ((code[1] & 0xc0) == 0x40)  {
		if (len < 3) return -1;

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,[%s+%d]\n",
					op, dstreg, srcreg, ((code[1] & 0x07) == 0x04) ? code[3] : code[2]);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t0x%x(%s),%s\n",
					op, ((code[1] & 0x07) == 0x04) ? code[3] : code[2], srcreg, dstreg);
	}

	return 0;
}

int op_notneg (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];

	if (len < 2) return -1;

	if (opts & BITS_8)
		get_dstreg8 (code[1], reg, sizeof(reg), opts);
	else if (opts & BITS_16)
		get_dstreg16 (code[2], reg, sizeof(reg), opts);
	else
		get_dstreg (code[1], reg, sizeof(reg), opts);

	snprintf (buf, buflen, "%s\t%s\n", op, reg);
	return 0;
}

int op_muldiv (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];

	if (len < 2) return -1;

	if (opts & BITS_8)
		get_dstreg8 (code[1], reg, sizeof(reg), opts);
	else if (opts & BITS_16)
		get_dstreg16 (code[2], reg, sizeof(reg), opts);
	else
		get_dstreg (code[1], reg, sizeof(reg), opts);
	
	snprintf (buf, buflen, "%s\t%s\n", op, reg);
	return 0;
}

