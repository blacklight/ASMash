#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_scal8 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char reg[8];

	if (len < 2) return -1;

	if (code[0] == 0x4)  {
		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\tal,0x%x\n", op, code[1]);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,al\n", op, code[1]);

		return 0;
	}

	switch ((code[0] & 0xf8) >> 3)  {
		case 0x16:
			get_dstreg8 (code[0], reg, sizeof(reg), opts);
			
			if ((opts & 0x1) == INTEL_FLAVOR)
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,0x%x\n", op, reg, code[1]);
			else
				snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t$0x%x,%s\n", op, code[1], reg);
			break;
	}

	return 0;
}

int op_reg8 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char srcreg[8], dstreg[8];

	if (len < 2) return -1;

	get_srcreg8 (code[1], srcreg, sizeof(srcreg), opts);

	if ((code[0] & 0x3) == 0x0)  {
		get_dstreg8 (code[1], dstreg, sizeof(dstreg), opts);

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,%s\n", op, dstreg, srcreg);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,%s\n", op, srcreg, dstreg);
	} else if ((code[0] & 0x3) == 0x2)  {
		get_dstreg (code[1], dstreg, sizeof(dstreg), opts);

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s,[%s]\n", op, srcreg, dstreg);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t(%s),%s\n", op, dstreg, srcreg);
	}

	return 0;
}

