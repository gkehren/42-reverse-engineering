#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char **argv, const char **envp)
{
	int v4; // [esp+14h] [ebp-2Ch] BYREF
	int v5; // [esp+3Ch] [ebp-4h]

	v5 = atoi(argv[1]);
	if ( v5 > 9 )
		return 1;
	memcpy(&v4, argv[2], 4 * v5);
	if ( v5 == 1464814662 )
		execl("/bin/sh", "sh", 0);
	return 0;
}
