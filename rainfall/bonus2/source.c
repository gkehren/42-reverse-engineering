#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__uint32_t language = 0;

int greetuser(char a1)
{
	char v2[72];

	switch ( language )
	{
		case 1:
		strcpy((char *)v2, "Hyvää päivää! ");
		break;
		case 2:
		strcpy((char *)v2, "Goedemiddag! ");
		break;
		case 0:
		strcpy((char *)v2, "Hello ");
		break;
	}
	strcat(v2, &a1);
	return puts(v2);
}

int main(int argc, const char **argv, const char **envp)
{
	char v4[76];
	char v5[76];
	char *v6;

	if ( argc != 3 )
		return 1;
	memset(v5, 0, sizeof(v5));
	strncpy(v5, argv[1], 40);
	strncpy(&v5[40], argv[2], 32);
	v6 = getenv("LANG");
	if ( v6 )
	{
		if ( !memcmp(v6, "fi", 2) )
		{
		language = 1;
		}
		else if ( !memcmp(v6, "nl", 2) )
		{
		language = 2;
		}
	}
	memcpy(v4, v5, sizeof(v4));
	return greetuser(v4[0]);
}
