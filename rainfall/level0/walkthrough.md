# level0

```bash
$ ls -l
total 732
-rwsr-x---+ 1 level1 users 747441 Mar  6  2016 level0
$ file level0
level0: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=0x85cf4024dbe79c7ccf4f30e7c601a356ce04f412, not stripped
$ ./level0
Segmentation fault (core dumped)
$ ./level0 arg
No !
$ gdb level0
(gdb) disas main
0x08048ed4 <+20>:    call   0x8049710 <atoi>
0x08048ed9 <+25>:    cmp    $0x1a7,%eax
(gdb) p/d 0x1a7
$1 = 423
```

Ici le programme fait un atoi sur l’argument passer au programme et le compare a 423

```bash
level0@RainFall:~$ ./level0 423
$ whoami
level1
$ cat /home/user/level1/.pass
1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a
```

FLAG: `1fe8a524fa4bec01ca4ea2a869af2a02260d4a7d5fe7e7c24d8617e6dca12d3a`
