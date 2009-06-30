#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elfshark.h>

int main (int argc, char **argv)  {
	u8 *code = NULL;
	struct sec_info s_info;

	if (!argv[1])  {
		fprintf (stderr, "Usage: %s <executable ELF file>\n", argv[0]);
		return 1;
	}

	strcpy (s_info.sec_name, ".text");

	if (!(code = AA_GetSectionContentFromELF(argv[1], &s_info)))  {
		fprintf (stderr, "Error: Unable to get .text content from %s\n", argv[1]);
		return 1;
	}

	printf ("%s\n", decode_to_asm (code, s_info.sec_size, s_info.sec_vaddr, INTEL_FLAVOR|DISP_BINARY));
	free(code);
}

