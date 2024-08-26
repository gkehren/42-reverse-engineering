#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char **argv, const char **envp)
{
	int v4[2]; // [esp+10h] [ebp-10h] BYREF
	int v5; // [esp+18h] [ebp-8h]
	int v6; // [esp+1Ch] [ebp-4h]

	if ( atoi(argv[1]) == 423 )
	{
		v4[0] = strdup("/bin/sh");
		v4[1] = 0;
		v6 = getegid();
		v5 = geteuid();
		setresgid(v6, v6, v6);
		setresuid(v5, v5, v5);
		execv("/bin/sh", v4);
	}
	else
	{
		fwrite("No !\n", 1, 5, stderr);
	}
	return 0;
}
