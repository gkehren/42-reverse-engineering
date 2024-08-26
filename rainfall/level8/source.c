#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__uint32_t auth;
__uint32_t service;

int main(int argc, const char **argv, const char **envp)
{
	__int8_t v4[5]; // [esp+20h] [ebp-88h] BYREF
	char v5[2]; // [esp+25h] [ebp-83h] BYREF
	char v6; // [esp+27h] [ebp-81h] BYREF

	while ( 1 )
	{
		printf("%p, %p \n", (const void *)auth, (const void *)service);
		if ( !fgets(v4, 128, stdin) )
		break;
		if ( !memcmp(v4, "auth ", 5u) )
		{
		auth = malloc(4);
		*(char *)auth = 0;
		if ( strlen(v5) <= 0x1E )
			strcpy(auth, v5);
		}
		if ( !memcmp(v4, "reset", 5u) )
		free(auth);
		if ( !memcmp(v4, "service", 6u) )
		service = strdup(&v6);
		if ( !memcmp(v4, "login", 5u) )
		{
		if ( *(char *)(auth + 32) )
			system("/bin/sh");
		else
			fwrite("Password:\n", 1, 10, stdout);
		}
	}
	return 0;
}
