#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int p()
{
	char v1[64]; // [esp+1Ch] [ebp-4Ch] BYREF
	const void *v2; // [esp+5Ch] [ebp-Ch]
	unsigned int retaddr; // [esp+6Ch] [ebp+4h]

	fflush(stdout);
	gets(v1);
	v2 = (const void *)retaddr;
	if ( (retaddr & 0xB0000000) == -1342177280 )
	{
		printf("(%p)\n", v2);
		_exit(1);
	}
	puts(v1);
	return strdup(v1);
}

int main(int argc, const char **argv, const char **envp)
{
	return p();
}
