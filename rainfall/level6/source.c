#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int n()
{
	return system("/bin/cat /home/user/level7/.pass");
}

int m()
{
	return puts("Nope");
}

int main(int argc, const char **argv, const char **envp)
{
	int (**v4)(void); // [esp+18h] [ebp-8h]
	int *v5; // [esp+1Ch] [ebp-4h]

	v5 = malloc(64);
	v4 = (int (**)(void))malloc(4);
	*v4 = m;
	strcpy(v5, argv[1]);
	return (*v4)();
}
