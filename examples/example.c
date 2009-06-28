#include <stdio.h>
#include <elfshark.h>

main()  {
	u8 code[] =
		"\xc1\xc8\x02"
		"\xb8\x04\x00\x00\x00"	/*mov    $0x4,%eax*/
		"\xbb\x01\x00\x00\x00"	/*mov    $0x1,%ebx*/
		"\xb9\x60\x80\x04\x08"	/*mov    $0x8048060,%ecx*/
		"\xba\x06\x00\x00\x00"	/*mov    $0x6,%edx*/
		"\xcd\x80"			/*int    $0x80*/
		"\xb8\x01\x00\x00\x00"	/*mov    $0x1,%eax*/
		"\xbb\x00\x00\x00\x00"	/*mov    $0x0,%ebx*/
		"\xcd\x80"			/*int    $0x80*/
		"\xc9"				/*leave*/
		"\xc3"				/*ret*/;
	
	// flags = 0 -> default ASM synthax: Intel
	printf ("%s\n", decode_to_asm (code, sizeof(code)-1, 0, 0));

	// To get the output in AT&T style:
	//printf ("%s\n", decode_to_asm (code, sizeof(code)-1, 0, AT_FLAVOUR));
}

