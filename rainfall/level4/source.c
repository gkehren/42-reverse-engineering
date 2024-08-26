#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int p(char *a1)
{
	return printf(a1);
}

int n()
{
	int result; // eax
	char v1[520]; // [esp+10h] [ebp-208h] BYREF

	fgets(v1, 512, stdin);
	p(v1);
	if ( result == 16930116 )
		return system("/bin/cat /home/user/level5/.pass");
	return result;
}

int main(int argc, const char **argv, const char **envp)
{
	return n();
}
