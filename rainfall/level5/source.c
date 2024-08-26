#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int o()
{
	system("/bin/sh");
	_exit(1);
}

int n()
{
	char v4[520]; // [esp+10h] [ebp-208h] BYREF

	fgets(v4, 512, stdin);
	printf(v4);
	exit(1);
}

int main(int argc, const char **argv, const char **envp)
{
	return n();
}
