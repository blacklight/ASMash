#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "elfshark.h"
#define	LINESIZE		0xff

char* decode_to_asm (u8 code[], u32 len, u32 init_addr, u8 opts)  {
	u32 i, increment = 0, buflen = 0;
	char* buf = NULL;
	char line[LINESIZE];

	if (!init_addr) init_addr = 0x08048000;

	for (i=0; i<len; i++)  {
		increment = 0;
		memset (line, 0x0, sizeof(line));

		switch (code[i])  {
			case 0x01:
			case 0x09:
			case 0x11:
			case 0x19:
			case 0x21:
			case 0x25:
			case 0x29:
			case 0x31:
			case 0x39:
			case 0x85:
			case 0x86:
			case 0x87:
			case 0x89:
			case 0xa1:
			case 0xa3:
				increment = 1;

				if ((code[i+1] & 0x07) == ESP) increment++;
				if ((code[i+1] & 0xc0) >> 6 == 0x1) increment++;
				
				if ((code[i+1] & 0xc0) >> 6 == 0x10)  {
					unknown (&(code[i]), 1, line, LINESIZE, opts);
					buflen += strlen(line);
					buf = (char*) realloc(buf, buflen);
					sprintf (buf, "%s%s", buf, line);
					continue;
				}

				switch (code[i])  {
					case 0x01:
						op_reg32 ("add", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x09:
						op_reg32 ("or",  code+i, increment+1, line, LINESIZE, opts); break;
					case 0x11:
						op_reg32 ("adc", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x19:
						op_reg32 ("sbb", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x21:
					case 0x25:
						op_reg32 ("and", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x29:
						op_reg32 ("sub", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x31:
						op_reg32 ("xor", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x39:
						op_reg32 ("cmp", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x85:
						op_reg32 ("test", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x86:
						op_reg32 ("xchg", code+i, increment+1, line, LINESIZE, opts|BITS_8); break;
					case 0x87:
						op_reg32 ("xchg", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x89:
						if ((code[i+1] & 0x7) == 0x5) increment = 5;
						op_reg32 ("mov", code+i, increment+1, line, LINESIZE, opts); break;
					case 0xa1:
					case 0xa3:
						increment = 4;
						op_reg32 ("mov", code+i, increment+1, line, LINESIZE, opts); break;
				}
		
				break;

			case 0x03:
			case 0x0b:
			case 0x13:
			case 0x1b:
			case 0x23:
			case 0x2b:
			case 0x33:
			case 0x3b:
			case 0x8b:
				increment = 1;

				if ((code[i+1] & 0x07) == ESP) increment++;
				if ((code[i+1] & 0xc0) >> 6 == 0x1) increment++;
				
				if ((code[i+1] & 0xc0) >> 6 == 0x10)  {
					unknown (&(code[i]), 1, line, LINESIZE, opts);
					buflen += strlen(line);
					buf = (char*) realloc(buf, buflen);
					sprintf (buf, "%s%s", buf, line);
					continue;
				}

				switch (code[i])  {
					case 0x03:
						op_reg32_inv ("add", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x0b:
						op_reg32_inv ("or",  code+i, increment+1, line, LINESIZE, opts); break;
					case 0x13:
						op_reg32_inv ("adc", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x1b:
						op_reg32_inv ("sbb", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x23:
						op_reg32_inv ("and", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x2b:
						op_reg32_inv ("sub", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x33:
						op_reg32_inv ("xor", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x3b:
						op_reg32_inv ("cmp", code+i, increment+1, line, LINESIZE, opts); break;
					case 0x8b:
						if ((code[i+1] & 0x7) == 0x5) increment = 5;
						op_reg32_inv ("mov", code+i, increment+1, line, LINESIZE, opts); break;
				}
		
				break;

			case 0xb8:
			case 0xb9:
			case 0xba:
			case 0xbb:
			case 0xbc:
			case 0xbd:
			case 0xbe:
			case 0xbf:
				increment = 4;
				op_scal32 ("mov", code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0x81:
				increment = 5;
				op_scal81 (code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0x83:
				increment = 2;
				op_scal83 (code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0x27:
			case 0x2f:
			case 0x37:
			case 0x60:
			case 0x61:
			case 0x90:
			case 0x91:
			case 0x92:
			case 0x93:
			case 0x94:
			case 0x95:
			case 0x96:
			case 0x97:
			case 0x98:
			case 0x99:
			case 0x9b:
			case 0x9c:
			case 0x9d:
			case 0x9e:
			case 0x9f:
			case 0xc3:
			case 0xc9:
			case 0xcb:
			case 0xce:
			case 0xcf:
			case 0xf4:
			case 0xf5:
			case 0xf8:
			case 0xf9:
			case 0xfa:
			case 0xfb:
			case 0xfc:
			case 0xfd:
				single_op (code[i], line, LINESIZE, opts);
				break;

			case 0xcd:
				interrupt (code+i, 2, line, LINESIZE, opts);
				increment = 1;
				break;

			case 0x66:
				if ((code[i+1] & 0xf0) == 0x50)  {
					increment = 1;

					( ((code[i+1] & 0x4) >> 3) == 0x0 )
						? op_pushpop ("push", code+i+1, increment+1, line, LINESIZE, opts|BITS_16)
						: op_pushpop ("pop" , code+i+1, increment+1, line, LINESIZE, opts|BITS_16);

					break;
				}

				increment = 2;

				if ((code[i+2] & 0x07) == ESP) increment++;
				if ((code[i+2] & 0xc0) >> 6 == 0x1) increment++;
				
				if ((code[i+2] & 0xc0) >> 6 == 0x10)  {
					unknown (&(code[i]), 1, line, LINESIZE, opts);
					buflen += strlen(line);
					buf = (char*) realloc(buf, buflen);
					sprintf (buf, "%s%s", buf, line);
					continue;
				}

				switch (code[i+1])  {
					case 0x01:
						op_reg32 ("add", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x09:
						op_reg32 ("or",  code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x11:
						op_reg32 ("adc", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x19:
						op_reg32 ("sbb", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x21:
						op_reg32 ("and", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x29:
						op_reg32 ("sub", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x31:
						op_reg32 ("xor", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x39:
						op_reg32 ("cmp", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;

					case 0x40:
					case 0x41:
					case 0x42:
					case 0x43:
					case 0x44:
					case 0x45:
					case 0x46:
					case 0x47:
					case 0x48:
					case 0x49:
					case 0x4a:
					case 0x4b:
					case 0x4c:
					case 0x4d:
					case 0x4e:
					case 0x4f:
						increment = 1;
						op_incdec (code+i, increment+1, line, LINESIZE, opts|BITS_16);
						break;

					case 0x85:
						op_reg32 ("test", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x87:
						op_reg32 ("xchg", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x89:
						op_reg32 ("mov", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					
					case 0x03:
						op_reg32_inv ("add", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x0b:
						op_reg32_inv ("or",  code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x13:
						op_reg32_inv ("adc", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x1b:
						op_reg32_inv ("sbb", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x23:
						op_reg32_inv ("and", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x2b:
						op_reg32_inv ("sub", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x33:
						op_reg32_inv ("xor", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x3b:
						op_reg32_inv ("cmp", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x8b:
						op_reg32_inv ("mov", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
					case 0x8d:
					case 0xc4:
					case 0xc5:
						if ((code[i+2] & 0xc0) == 0x00)
							increment = 2;
						else if ((code[i+2] & 0xc0) == 0x40)
							increment = 3;

						if ((code[i+2] & 0x07) == 0x04)
							increment++;

						switch (code[i+1])  {
							case 0x8d:
								op_lea32 ("lea", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
							case 0xc4:
								op_lea32 ("les", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
							case 0xc5:
								op_lea32 ("lds", code+i+1, increment+1, line, LINESIZE, opts|BITS_16); break;
						}

						break;

					case 0xe4:
					case 0xe5:
					case 0xe6:
					case 0xe7:
					case 0xec:
					case 0xed:
					case 0xee:
					case 0xef:
						if ((code[i+1] >= 0xe4) && (code[i+1] <= 0xe7))
							increment = 2;
						else
							increment = 1;

						op_inout (code+i, increment+1, line, LINESIZE, opts|BITS_16);
						break;

					case 0xf6:
					case 0xf7:
						increment = 2;

						if (code[i+2] >= 0xd0 && code[i+2] <= 0xd7)
							op_notneg ("not", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						else if (code[i+2] >= 0xd8 && code[i+2] <= 0xdf)
							op_notneg ("neg", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						else if (code[i+2] >= 0xe0 && code[i+2] <= 0xe7)
							op_muldiv ("mul", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						else if (code[i+2] >= 0xe8 && code[i+2] <= 0xef)
							op_muldiv ("imul", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						else if (code[i+2] >= 0xf0 && code[i+2] <= 0xf7)
							op_muldiv ("div", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						else if (code[i+2] >= 0xf8)
							op_muldiv ("idiv", code+i, increment+1, line, LINESIZE, opts|BITS_16);
						break;
				}
		
				break;

			case 0x70:
			case 0x71:
			case 0x72:
			case 0x73:
			case 0x74:
			case 0x75:
			case 0x76:
			case 0x77:
			case 0x78:
			case 0x79:
			case 0x7a:
			case 0x7b:
			case 0x7c:
			case 0x7d:
			case 0x7e:
			case 0x7f:
			case 0xe0:
			case 0xe1:
			case 0xe2:
			case 0xe8:
			case 0xe9:
			case 0xeb:
				switch (code[i])  {
					case 0xe0:
						increment = 1;
						op_jmp ("loopne", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts);
						break;

					case 0xe1:
						increment = 1;
						op_jmp ("loope", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts);
						break;

					case 0xe2:
						increment = 1;
						op_jmp ("loop", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts);
						break;

					case 0xe9:
					case 0xeb:
						increment = (code[i] == 0xeb) ? 1 : 4;
						op_jmp ("jmp", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts);
						break;

					case 0xe8:
						increment = 4;
						op_jmp ("call", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts);
						break;

					case 0x70:
						increment = 1;
						op_jmp ("jo", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x71:
						increment = 1;
						op_jmp ("jno", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x72:
						increment = 1;
						op_jmp ("jb", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x73:
						increment = 1;
						op_jmp ("jae", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x74:
						increment = 1;
						op_jmp ("je", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x75:
						increment = 1;
						op_jmp ("jne", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x76:
						increment = 1;
						op_jmp ("jbe", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x77:
						increment = 1;
						op_jmp ("ja", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x78:
						increment = 1;
						op_jmp ("js", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x79:
						increment = 1;
						op_jmp ("jns", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7a:
						increment = 1;
						op_jmp ("jp", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7b:
						increment = 1;
						op_jmp ("jnp", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7c:
						increment = 1;
						op_jmp ("jl", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7d:
						increment = 1;
						op_jmp ("jge", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7e:
						increment = 1;
						op_jmp ("jle", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;

					case 0x7f:
						increment = 1;
						op_jmp ("jg", code+i, increment+1, line, LINESIZE, init_addr + i + increment + 1, opts); break;
				}

				break;

			case 0x50:
			case 0x51:
			case 0x52:
			case 0x53:
			case 0x54:
			case 0x55:
			case 0x56:
			case 0x57:
			case 0x58:
			case 0x59:
			case 0x5a:
			case 0x5b:
			case 0x5c:
			case 0x5d:
			case 0x5e:
			case 0x5f:
				( ((code[i] & 0x4) >> 3) == 0x0 )
					? op_pushpop ("push", code+i, increment+1, line, LINESIZE, opts)
					: op_pushpop ("pop" , code+i, increment+1, line, LINESIZE, opts);

				break;

			case 0x68:
				increment = 4;
				op_pushpop ("push", code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0xff:
				switch ((code[i+1] & 0xc0) >> 6)  {
					case 0x1:
						increment = ((code[i+1] & 0x7) == 0x4) ? 3 : 2;
						break;

					default:
						increment = ((code[i+1] & 0x7) == 0x4) ? 2 : 1;
						break;
				}

				switch ((code[i+1] & 0x30) >> 4)  {
					case 0x01:
						op_jmp_ff ("call", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x02:
						op_jmp_ff ("jmp" , code+i, increment+1, line, LINESIZE, opts); break;
				}

				break;

			case 0x04:
			case 0xb0:
			case 0xb1:
			case 0xb2:
			case 0xb3:
			case 0xb4:
			case 0xb5:
			case 0xb6:
			case 0xb7:
				increment = 1;

				if (code[i] == 0x04)  {
					op_scal8 ("add", code+i, increment+1, line, LINESIZE, opts); break;
				}

				op_scal8 ("mov", code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0x00:
			case 0x02:
			case 0x08:
			case 0x0a:
			case 0x10:
			case 0x12:
			case 0x18:
			case 0x1a:
			case 0x20:
			case 0x22:
			case 0x28:
			case 0x2a:
			case 0x30:
			case 0x32:
			case 0x38:
			case 0x3a:
			case 0x84:
			case 0x88:
			case 0x8a:
				increment = 1;

				switch (code[i])  {
					case 0x00:
					case 0x02:
					case 0x04:
						op_reg8 ("add", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x08:
					case 0x0a:
						op_reg8 ("or", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x10:
					case 0x12:
						op_reg8 ("adc", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x18:
					case 0x1a:
						op_reg8 ("sbb", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x20:
					case 0x22:
						op_reg8 ("sbb", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x28:
					case 0x2a:
						op_reg8 ("sub", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x30:
					case 0x32:
						op_reg8 ("xor", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x38:
					case 0x3a:
						op_reg8 ("cmp", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x84:
						op_reg8 ("test", code+i, increment+1, line, LINESIZE, opts); break;

					case 0x88:
					case 0x8a:
						op_reg8 ("mov", code+i, increment+1, line, LINESIZE, opts); break;
				}

				break;

			case 0x40:
			case 0x41:
			case 0x42:
			case 0x43:
			case 0x44:
			case 0x45:
			case 0x46:
			case 0x47:
			case 0x48:
			case 0x49:
			case 0x4a:
			case 0x4b:
			case 0x4c:
			case 0x4d:
			case 0x4e:
			case 0x4f:
				op_incdec (&(code[i]), 1, line, LINESIZE, opts);
				break;

			case 0xfe:
				increment = 1;

				if ((code[i+1] & 0xc0) == 0xc0)
					op_incdec (code+i, increment+1, line, LINESIZE, opts|BITS_8);
				break;

			case 0x8d:
			case 0xc4:
			case 0xc5:
				if ((code[i+1] & 0xc0) == 0x00)
					increment = 1;
				else if ((code[i+1] & 0xc0) == 0x40)
					increment = 2;

				if ((code[i+1] & 0x07) == 0x04)
					increment++;

				switch (code[i])  {
					case 0x8d:
						op_lea32 ("lea", code+i, increment+1, line, LINESIZE, opts); break;
					case 0xc4:
						op_lea32 ("les", code+i, increment+1, line, LINESIZE, opts); break;
					case 0xc5:
						op_lea32 ("lds", code+i, increment+1, line, LINESIZE, opts); break;
				}

				break;

			case 0xe4:
			case 0xe5:
			case 0xe6:
			case 0xe7:
			case 0xec:
			case 0xed:
			case 0xee:
			case 0xef:
				if ((code[i] >= 0xe4) && (code[i] <= 0xe7))
					increment = 1;
				else
					increment = 0;

				op_inout (code+i, increment+1, line, LINESIZE, opts);
				break;

			case 0x0f:
				if (code[i+1] == 0xa2)  {
					increment = 1;
					snprintf (line, LINESIZE, "cpuid\n");
				}

				break;

			case 0xf6:
			case 0xf7:
				increment = 1;

				if (code[i+1] >= 0xd0 && code[i+1] <= 0xd7)
					op_notneg ("not", code+i, increment+1, line, LINESIZE, (code[i] == 0xf6) ? opts|BITS_8 : opts);
				else if (code[i+1] >= 0xd8 && code[i+1] <= 0xdf)
					op_notneg ("neg", code+i, increment+1, line, LINESIZE, (code[i] == 0xf6) ? opts|BITS_8 : opts);
				else if (code[i+1] >= 0xe0 && code[i+1] <= 0xe7)
					op_muldiv ("mul", code+i, increment+1, line, LINESIZE, opts|BITS_16);
				else if (code[i+1] >= 0xe8 && code[i+1] <= 0xef)
					op_muldiv ("imul", code+i, increment+1, line, LINESIZE, opts|BITS_16);
				else if (code[i+1] >= 0xf0 && code[i+1] <= 0xf7)
					op_muldiv ("div", code+i, increment+1, line, LINESIZE, opts|BITS_16);
				else if (code[i+1] >= 0xf8)
					op_muldiv ("idiv", code+i, increment+1, line, LINESIZE, opts|BITS_16);
				break;

			case 0xc1:
			case 0xd1:
				increment = (code[i] == 0xc1) ? 2 : 1;

				if (code[i+1] >= 0xc0 && code[i+1] <= 0xc7)
					op_rotsh ("rol", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xc8 && code[i+1] <= 0xcf)
					op_rotsh ("ror", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xd0 && code[i+1] <= 0xd7)
					op_rotsh ("rcl", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xd8 && code[i+1] <= 0xdf)
					op_rotsh ("rcr", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xe0 && code[i+1] <= 0xe7)
					op_rotsh ("shl", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xe8 && code[i+1] <= 0xef)
					op_rotsh ("shr", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xf0 && code[i+1] <= 0xf7)
					op_rotsh ("sal", code+i, increment+1, line, LINESIZE, opts);
				else if (code[i+1] >= 0xf8)
					op_rotsh ("sar", code+i, increment+1, line, LINESIZE, opts);
				break;

			default:
				unknown (&(code[i]), 1, line, LINESIZE, opts);
				break;
		}
		
		buflen += strlen(line);
		buf = (char*) realloc(buf, buflen);
		sprintf (buf, "%s%s", buf, line);
		i += increment;
	}

	return buf;
}

