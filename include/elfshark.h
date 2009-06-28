/**
 * The files in this directory and elsewhere which refer to this LICENCE
 * file are part of ElfShark, the library for disassembling/assembling
 * binary code.
 *
 * Copyright (C) 2009 BlackLight
 *
 * uSock is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 or (at your option) any later 
 * version.
 *
 * uSock is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with uSock; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA.
 *
 * As a special exception, if other files instantiate templates or use
 * macros or inline functions from these files, or you compile these
 * files and link them with other works to produce a work based on these
 * files, these files do not by themselves cause the resulting work to be
 * covered by the GNU General Public License. However the source code for
 * these files must still be made available in accordance with section (3)
 * of the GNU General Public License.
 *
 * This exception does not invalidate any other reasons why a work based on
 * this file might be covered by the GNU General Public License.
 */


#ifndef	__ELFSHARK_H
#define	__ELFSHARK_H

#define	INSTRLEN	24

#define	EAX	0x0
#define	ECX	0x1
#define	EDX	0x2
#define	EBX	0x3
#define	ESP	0x4
#define	EBP	0x5
#define	ESI	0x6
#define	EDI	0x7

#define	AX	0x0
#define	CX	0x1
#define	DX	0x2
#define	BX	0x3
#define	SP	0x4
#define	BP	0x5
#define	SI	0x6
#define	DI	0x7

#define	AL	0x0
#define	CL	0x1
#define	DL	0x2
#define	BL	0x3
#define	AH	0x4
#define	CH	0x5
#define	DH	0x6
#define	BH	0x7

#define	INTEL_FLAVOR	0x0
#define	AT_FLAVOR		0x1
#define	DISP_BINARY	0x2
#define	BITS_16		0x4
#define	BITS_8		0x8

typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned long int u32;

unsigned char* get_executable_elf_code(char *fname, int *code_size, int *addr);
char* decode_to_asm (u8 code[], u32 len, u32 init_addr, u8 opts);

void get_srcreg   (u8 code, char srcreg[], u8 len, u8 opts);
void get_srcreg8  (u8 code, char srcreg[], u8 len, u8 opts);
void get_srcreg16 (u8 code, char srcreg[], u8 len, u8 opts);

void get_dstreg   (u8 code, char dstreg[], u8 len, u8 opts);
void get_dstreg8  (u8 code, char dstreg[], u8 len, u8 opts);
void get_dstreg16 (u8 code, char dstreg[], u8 len, u8 opts);

void unknown (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
void single_op (u8 code, char buf[], u8 buflen, u8 opts);
void op_incdec (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);

int interrupt (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_reg32 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_scal32 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_reg32_inv (char* op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_scal81 (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_scal83 (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_jmp (char* op, u8 code[], u8 len, char buf[], u8 buflen, u32 addr, u8 opts);
int op_jmp_ff (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_pushpop (char* op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_scal8 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_reg8  (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_lea32 (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_inout (u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_notneg (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);
int op_muldiv (char *op, u8 code[], u8 len, char buf[], u8 buflen, u8 opts);

#endif

