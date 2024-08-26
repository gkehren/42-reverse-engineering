#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char unk_80486A0[] = " - ";

void p(char *a1, char *a2)
{
	char v3[4104]; // [esp+10h] [ebp-1008h] BYREF

	puts(a2);
	read(0, v3, 4096);
	*(__uint8_t *)strchr(v3, 10) = 0;
	strncpy(a1, v3, 20);
}

void pp(char *a1)
{
	char v2[20]; // [esp+28h] [ebp-30h] BYREF
	char v3[28]; // [esp+3Ch] [ebp-1Ch] BYREF
	__uint32_t len;

	p(v2, unk_80486A0);
	p(v3, unk_80486A0);
	strcpy(a1, v2);
	len = strlen(a1);
	a1[len] = ' ';
	a1[len + 1] = 0;
	strcat(a1, v3);
}

int main(int argc, const char **argv, const char **envp)
{
	__uint8_t v4[42]; // [esp+16h] [ebp-2Ah] BYREF

	pp(v4);
	puts(v4);
	return 0;
}
