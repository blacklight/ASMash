#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>

#include "elfshark.h"

unsigned char* get_executable_elf_code(char *fname, int *code_size, int *addr)  {
	unsigned char *code;
	int fd, hlen, s_off;
	Elf32_Ehdr elfhdr;

	if (!fname)
		return NULL;

	if ((fd=open(fname, O_RDONLY))<0)
		return NULL;

	if (read(fd, &elfhdr, sizeof(Elf32_Ehdr)) <= 0)
		return NULL;

	hlen = elfhdr.e_phentsize*elfhdr.e_phnum + elfhdr.e_ehsize;
	s_off = elfhdr.e_shoff;
	*code_size = s_off-hlen;

	if (!(code = (unsigned char*) malloc(*code_size)))
		return NULL;

	lseek (fd,hlen,SEEK_SET);
	
	if (read(fd, code, *code_size) <= 0)
		return NULL;

	*addr=elfhdr.e_entry;
	close(fd);
	return code;
}

