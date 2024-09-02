# level03

```bash
$ ls -l
total 8
-rwsr-s---+ 1 level04 users 7677 Sep 10  2016 level03
$ file level03
level03: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x9e834af52f4b2400d5bd38b3dac04d1a5faa1729, not stripped
$ gdb -q ./level03
Reading symbols from /home/users/level03/level03...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0804843c  _init
0x08048480  printf
0x08048480  printf@plt
0x08048490  fflush
0x08048490  fflush@plt
0x080484a0  getchar
0x080484a0  getchar@plt
0x080484b0  time
0x080484b0  time@plt
0x080484c0  __stack_chk_fail
0x080484c0  __stack_chk_fail@plt
0x080484d0  puts
0x080484d0  puts@plt
0x080484e0  system
0x080484e0  system@plt
0x080484f0  __gmon_start__
0x080484f0  __gmon_start__@plt
0x08048500  srand
0x08048500  srand@plt
0x08048510  __libc_start_main
0x08048510  __libc_start_main@plt
0x08048520  rand
0x08048520  rand@plt
0x08048530  __isoc99_scanf
0x08048530  __isoc99_scanf@plt
0x08048540  _start
0x08048570  __do_global_dtors_aux
0x080485d0  frame_dummy
0x080485f4  clear_stdin
0x08048617  get_unum
0x0804864f  prog_timeout
0x08048660  decrypt
0x08048747  test
0x0804885a  main
0x080488f0  __libc_csu_init
0x08048960  __libc_csu_fini
0x08048962  __i686.get_pc_thunk.bx
0x08048970  __do_global_ctors_aux
0x0804899c  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x0804885a <+0>:     push   %ebp
   0x0804885b <+1>:     mov    %esp,%ebp
   0x0804885d <+3>:     and    $0xfffffff0,%esp
   0x08048860 <+6>:     sub    $0x20,%esp
   0x08048863 <+9>:     push   %eax
   0x08048864 <+10>:    xor    %eax,%eax
   0x08048866 <+12>:    je     0x804886b <main+17>
   0x08048868 <+14>:    add    $0x4,%esp
   0x0804886b <+17>:    pop    %eax
   0x0804886c <+18>:    movl   $0x0,(%esp)
   0x08048873 <+25>:    call   0x80484b0 <time@plt>
   0x08048878 <+30>:    mov    %eax,(%esp)
   0x0804887b <+33>:    call   0x8048500 <srand@plt>
   0x08048880 <+38>:    movl   $0x8048a48,(%esp)
   0x08048887 <+45>:    call   0x80484d0 <puts@plt>
   0x0804888c <+50>:    movl   $0x8048a6c,(%esp)
   0x08048893 <+57>:    call   0x80484d0 <puts@plt>
   0x08048898 <+62>:    movl   $0x8048a48,(%esp)
   0x0804889f <+69>:    call   0x80484d0 <puts@plt>
   0x080488a4 <+74>:    mov    $0x8048a7b,%eax
   0x080488a9 <+79>:    mov    %eax,(%esp)
   0x080488ac <+82>:    call   0x8048480 <printf@plt>
   0x080488b1 <+87>:    mov    $0x8048a85,%eax
   0x080488b6 <+92>:    lea    0x1c(%esp),%edx
   0x080488ba <+96>:    mov    %edx,0x4(%esp)
   0x080488be <+100>:   mov    %eax,(%esp)
   0x080488c1 <+103>:   call   0x8048530 <__isoc99_scanf@plt>
   0x080488c6 <+108>:   mov    0x1c(%esp),%eax
   0x080488ca <+112>:   movl   $0x1337d00d,0x4(%esp) # arg de test
   0x080488d2 <+120>:   mov    %eax,(%esp)
   0x080488d5 <+123>:   call   0x8048747 <test>
   0x080488da <+128>:   mov    $0x0,%eax
   0x080488df <+133>:   leave
   0x080488e0 <+134>:   ret
End of assembler dump.
```

```bash
$ strings -d ./level03
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
fflush
srand
__isoc99_scanf
puts
time
__stack_chk_fail
printf
getchar
stdout
system
__libc_start_main
GLIBC_2.7
GLIBC_2.4
GLIBC_2.0
PTRh`
QVhZ
Q}|u
`sfg
~sf{
}|a3
@^_]
UWVS
[^_]
Congratulations!
/bin/sh
Invalid Password
***********************************
*               level03         **
Password:
;*2$"
```

```bash
Q}|u`sfg~sf{}|a3 # qui correspond a Congratulations!
```

```bash
$ nano /tmp/decrypt.py
cipher_text = "Q}|u`sfg~sf{}|a3"
target_text = "Congratulations!"

key = ''.join(chr(ord(e) ^ ord(t)) for e, t in zip(cipher_text, target_text))
print("Key:", key)

$ python /tmp/decrypt.py
('Key:', '\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12\x12')
```

La fonction test prend `0x1337d00d` alors `0x1337d00d - 0x12 = 322424827`

```bash
$ ./level03
***********************************
*               level03         **
***********************************
Password:322424827
$ cat /home/users/level04/.pass
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```

FLAG: `kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf`