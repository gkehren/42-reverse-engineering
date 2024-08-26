#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int v()
{
	int result; // eax
	char v1[520]; // [esp+10h] [ebp-208h] BYREF

	fgets(v1, 512, stdin);
	printf(v1);
	if ( result == 64 )
	{
		fwrite("Wait what?!\n", 1, 12, stdout);
		return system("/bin/sh");
	}
	return result;
}

int main(int argc, const char **argv, const char **envp)
{
	return v();
}
