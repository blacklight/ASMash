#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

#include "elfshark.h"

int AA_GetSectionInfoFromELF (const char *fname, struct sec_info *info)  {
	int i, j, fd, pos, strtab_found = 0, sec_found = 0;
	char *strtab = NULL;
	Elf32_Ehdr elfhdr;
	Elf32_Shdr shdr, strtab_hdr;

	if ((fd=open(fname,O_RDONLY))<0)
		return -1;
	
	if (read(fd,&elfhdr,sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr))
		return -1;

	if (elfhdr.e_ident[0] != '\x7f' ||
			elfhdr.e_ident[1] != 'E' ||
			elfhdr.e_ident[2] != 'L' ||
			elfhdr.e_ident[3] != 'F')
		return -1;

	if (lseek(fd, elfhdr.e_shoff, SEEK_SET) != elfhdr.e_shoff)
		return -1;

	for (i=0; i < elfhdr.e_shnum && !strtab_found; i++)  {
		if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
			return -1;

		if (shdr.sh_type == SHT_STRTAB)  {
			pos = lseek (fd, 0, SEEK_CUR);
			
			if (!(strtab = (char*) malloc(shdr.sh_size)))
				return -1;

			if (lseek(fd, shdr.sh_offset, SEEK_SET) != shdr.sh_offset)
				return -1;

			if (read(fd, strtab, shdr.sh_size) != shdr.sh_size)
				return -1;

			for (j=0; j < shdr.sh_size - strlen(info->sec_name) && !strtab_found; j++)
				if (!strncmp(info->sec_name, strtab+j, strlen(info->sec_name)))  {
					strtab_hdr = shdr;
					strtab_found = 1;
				}

			lseek (fd, pos, SEEK_SET);
		}
	}

	if (!strtab_found)
		return -1;

	if (lseek(fd, elfhdr.e_shoff, SEEK_SET) != elfhdr.e_shoff)
		return -1;

	for (i=0; i < elfhdr.e_shnum && !sec_found; i++)  {
		if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr))
			return -1;

		if (shdr.sh_name < strtab_hdr.sh_size)  {
			if (!strncmp(info->sec_name, strtab + shdr.sh_name, strlen(info->sec_name)))  {
				info->sec_vaddr  = shdr.sh_addr;
				info->sec_offset = shdr.sh_offset;
				info->sec_size   = shdr.sh_size;
				sec_found = 1;
			}
		}
	}

	if (!sec_found)
		return -1;

	free(strtab);
	close(fd);
	return 0;
}

u8* AA_GetSectionContentFromELF (const char *fname, struct sec_info *s_info)  {
	int fd;
	u8 *content = NULL;

	if (AA_GetSectionInfoFromELF(fname, s_info) < 0)
		return NULL;

	if (!(content = (u8*) malloc(s_info->sec_size)))
		return NULL;

	if ((fd=open(fname, O_RDONLY))<0)
		return NULL;

	if (lseek(fd, s_info->sec_offset, SEEK_SET) != s_info->sec_offset)
		return NULL;

	if (read(fd, content, s_info->sec_size) != s_info->sec_size)
		return NULL;

	close(fd);
	return content;
}

