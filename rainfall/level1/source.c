#include <stdio.h>
#include <stdlib.h>

int run()
{
	fwrite("Good... Wait what?\n", 1, 19, stdout);
	return system("/bin/sh");
}

int main(int argc, const char **argv, const char **envp)
{
	int v4; // [esp+10h] [ebp-40h] BYREF

	return gets(&v4);
}

