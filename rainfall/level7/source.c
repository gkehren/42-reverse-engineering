#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

char c[80];

int m()
{
	int v0; // eax

	v0 = time(0);
	return printf("%s - %d\n", c, v0);
}

int main(int argc, const char **argv, const char **envp)
{
	FILE *v3; // eax
	int *v5; // [esp+18h] [ebp-8h]
	int *v6; // [esp+1Ch] [ebp-4h]

	v6 = (int *)malloc(8);
	*v6 = 1;
	v6[1] = (int)malloc(8);
	v5 = (int *)malloc(8);
	*v5 = 2;
	v5[1] = (int)malloc(8);
	strcpy((char *)v6[1], argv[1]);
	strcpy((char *)v5[1], argv[2]);
	v3 = fopen("/home/user/level8/.pass", "r");
	fgets(c, 68, v3);
	puts("~~");
	return 0;
}
