#include <stdio.h>
#include <string.h>
#include "elfshark.h"

int op_pushpop (char* op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts)  {
	char dstreg[8];
	u32 var;

	if (len < 1) return -1;

	if (code[0] == 0x68)  {
		if (len < 5) return -1;
		memcpy (&var, code+1, sizeof(var));

		if ((opts & 0x1) == INTEL_FLAVOR)
			snprintf (buf+strlen(buf), buflen-strlen(buf), "push\t0x%x\n", var);
		else
			snprintf (buf+strlen(buf), buflen-strlen(buf), "push\t$0x%x\n", var);

		return 0;
	}

	if (opts & BITS_16)
		get_dstreg16(code[0], dstreg, sizeof(dstreg), opts);
	else
		get_dstreg(code[0], dstreg, sizeof(dstreg), opts);

	snprintf (buf+strlen(buf), buflen-strlen(buf), "%s\t%s\n", op, dstreg);
	return 0;
}

