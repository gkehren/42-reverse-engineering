# level09

```bash
$ ls -l
total 12
-rwsr-sr-x 1 flag09 level09 7640 Mar  5  2016 level09
----r--r-- 1 flag09 level09   26 Mar  5  2016 token
$ ./level09
You need to provied only one arg.
$ ./level09 getflag
gfvipfm

```

On voit que les lettres sont décalées selon leur index dans la string (getflag[6] == ‘g’, ‘g’ + 6 == m)

```bash
$ cd /tmp
$ vim main.c
```

```c
#include <stdio.h>

int main(int argc, char **argv)
{
  if (argc != 2)
    return printf("One arg is required\n");

  int i = 0;

  while (argv[1][i] != '\0')
  {
    printf("%c", argv[1][i] - i);
    i++;
  }
  printf("\n");
  return 0;
}
```

```bash
$ gcc main.c
$ ./a.out $(cat ~/token)
f3iji1ju5yuevaus41q1afiuq
$ su flag09
Password: f3iji1ju5yuevaus41q1afiuq
Don't forget to launch getflag !
$ getflag
Check flag.Here is your token : s5cAJpM8ev6XHw998pRWG728z
```
