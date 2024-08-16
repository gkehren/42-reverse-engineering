# level00

```bash
$ find / -user flag00 2> /dev/null
/usr/sbin/john
/rofs/usr/sbin/john

$ cat /usr/sbin/john
cdiiddwpgswtgt

$ su flag00
Password: cdiiddwpgswtgt
su: Authentication failure
```

Code César avec un décalage de 15:

- **c** -> c−15=n
- **d** -> d−15=o
- **i** -> i−15=t
- **i** -> i−15=t
- **d** -> d−15=o
- **d** -> d−15=o
- **w** -> w−15=h
- **p** -> p−15=a
- **g** -> g−15=r
- **s** -> s−15=d
- **w** -> w−15=h
- **t** -> t−15=e
- **g** -> g−15=r
- **t** -> t−15=e

Le message déchiffré est donc : **nottoohardhere**.

```bash
$ su flag00
Password: nottoohardhere
Don't forget to launch getflag !

$ getflag
Check flag.Here is your token : x24ti5gi3x0ol2eh4esiuxias
```
