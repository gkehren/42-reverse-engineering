# bonus3

```bash
$ ls -l
total 8
-rwsr-s---+ 1 end users 5595 Mar  6  2016 bonus3
$ file bonus3
bonus3: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x530d693450de037e44d1186904401c8f8064874b, not stripped
$ gdb -q ./bonus3
Reading symbols from /home/user/bonus3/bonus3...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0804836c  _init
0x080483b0  strcmp
0x080483b0  strcmp@plt
0x080483c0  fclose
0x080483c0  fclose@plt
0x080483d0  fread
0x080483d0  fread@plt
0x080483e0  puts
0x080483e0  puts@plt
0x080483f0  __gmon_start__
0x080483f0  __gmon_start__@plt
0x08048400  __libc_start_main
0x08048400  __libc_start_main@plt
0x08048410  fopen
0x08048410  fopen@plt
0x08048420  execl
0x08048420  execl@plt
0x08048430  atoi
0x08048430  atoi@plt
0x08048440  _start
0x08048470  __do_global_dtors_aux
0x080484d0  frame_dummy
0x080484f4  main
0x08048620  __libc_csu_init
0x08048690  __libc_csu_fini
0x08048692  __i686.get_pc_thunk.bx
0x080486a0  __do_global_ctors_aux
0x080486cc  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x080484f4 <+0>:     push   %ebp
   0x080484f5 <+1>:     mov    %esp,%ebp
   0x080484f7 <+3>:     push   %edi
   0x080484f8 <+4>:     push   %ebx
   0x080484f9 <+5>:     and    $0xfffffff0,%esp
   0x080484fc <+8>:     sub    $0xa0,%esp
   0x08048502 <+14>:    mov    $0x80486f0,%edx
   0x08048507 <+19>:    mov    $0x80486f2,%eax
   0x0804850c <+24>:    mov    %edx,0x4(%esp)
   0x08048510 <+28>:    mov    %eax,(%esp)
   0x08048513 <+31>:    call   0x8048410 <fopen@plt>
   0x08048518 <+36>:    mov    %eax,0x9c(%esp)
   0x0804851f <+43>:    lea    0x18(%esp),%ebx
   0x08048523 <+47>:    mov    $0x0,%eax
   0x08048528 <+52>:    mov    $0x21,%edx
   0x0804852d <+57>:    mov    %ebx,%edi
   0x0804852f <+59>:    mov    %edx,%ecx
   0x08048531 <+61>:    rep stos %eax,%es:(%edi)
   0x08048533 <+63>:    cmpl   $0x0,0x9c(%esp)
   0x0804853b <+71>:    je     0x8048543 <main+79>
   0x0804853d <+73>:    cmpl   $0x2,0x8(%ebp)
   0x08048541 <+77>:    je     0x804854d <main+89>
   0x08048543 <+79>:    mov    $0xffffffff,%eax
   0x08048548 <+84>:    jmp    0x8048615 <main+289>
   0x0804854d <+89>:    lea    0x18(%esp),%eax
   0x08048551 <+93>:    mov    0x9c(%esp),%edx
   0x08048558 <+100>:   mov    %edx,0xc(%esp)
   0x0804855c <+104>:   movl   $0x42,0x8(%esp)
   0x08048564 <+112>:   movl   $0x1,0x4(%esp)
   0x0804856c <+120>:   mov    %eax,(%esp)
   0x0804856f <+123>:   call   0x80483d0 <fread@plt>
   0x08048574 <+128>:   movb   $0x0,0x59(%esp)
   0x08048579 <+133>:   mov    0xc(%ebp),%eax
   0x0804857c <+136>:   add    $0x4,%eax
   0x0804857f <+139>:   mov    (%eax),%eax
   0x08048581 <+141>:   mov    %eax,(%esp)
   0x08048584 <+144>:   call   0x8048430 <atoi@plt>
   0x08048589 <+149>:   movb   $0x0,0x18(%esp,%eax,1)
   0x0804858e <+154>:   lea    0x18(%esp),%eax
   0x08048592 <+158>:   lea    0x42(%eax),%edx
   0x08048595 <+161>:   mov    0x9c(%esp),%eax
   0x0804859c <+168>:   mov    %eax,0xc(%esp)
   0x080485a0 <+172>:   movl   $0x41,0x8(%esp)
   0x080485a8 <+180>:   movl   $0x1,0x4(%esp)
   0x080485b0 <+188>:   mov    %edx,(%esp)
   0x080485b3 <+191>:   call   0x80483d0 <fread@plt>
   0x080485b8 <+196>:   mov    0x9c(%esp),%eax
   0x080485bf <+203>:   mov    %eax,(%esp)
   0x080485c2 <+206>:   call   0x80483c0 <fclose@plt>
   0x080485c7 <+211>:   mov    0xc(%ebp),%eax
   0x080485ca <+214>:   add    $0x4,%eax
   0x080485cd <+217>:   mov    (%eax),%eax
   0x080485cf <+219>:   mov    %eax,0x4(%esp)
   0x080485d3 <+223>:   lea    0x18(%esp),%eax
   0x080485d7 <+227>:   mov    %eax,(%esp)
   0x080485da <+230>:   call   0x80483b0 <strcmp@plt>
   0x080485df <+235>:   test   %eax,%eax
   0x080485e1 <+237>:   jne    0x8048601 <main+269>
   0x080485e3 <+239>:   movl   $0x0,0x8(%esp)
   0x080485eb <+247>:   movl   $0x8048707,0x4(%esp)
   0x080485f3 <+255>:   movl   $0x804870a,(%esp)
   0x080485fa <+262>:   call   0x8048420 <execl@plt>
   0x080485ff <+267>:   jmp    0x8048610 <main+284>
   0x08048601 <+269>:   lea    0x18(%esp),%eax
   0x08048605 <+273>:   add    $0x42,%eax
   0x08048608 <+276>:   mov    %eax,(%esp)
   0x0804860b <+279>:   call   0x80483e0 <puts@plt>
   0x08048610 <+284>:   mov    $0x0,%eax
   0x08048615 <+289>:   lea    -0x8(%ebp),%esp
   0x08048618 <+292>:   pop    %ebx
   0x08048619 <+293>:   pop    %edi
   0x0804861a <+294>:   pop    %ebp
   0x0804861b <+295>:   ret
End of assembler dump.
```

```bash
# Decompile main
undefined4 main(int param_1,int param_2)
{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  byte bVar4;
  undefined4 local_98 [16];
  undefined local_57;
  char local_56 [66];
  FILE *local_14;

  bVar4 = 0;
  local_14 = fopen("/home/user/end/.pass","r");
  puVar3 = local_98;
  for (iVar2 = 0x21; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = 0;
    puVar3 = puVar3 + (uint)bVar4 * -2 + 1;
  }
  # si erreur lors de la lecture du .pass ou pas d'argument
  if ((local_14 == (FILE *)0x0) || (param_1 != 2)) {
    uVar1 = 0xffffffff;
  }
  else {
    fread(local_98,1,0x42,local_14);
    local_57 = 0;
    iVar2 = atoi(*(char **)(param_2 + 4)); # convertit argv[1] en int
    *(undefined *)((int)local_98 + iVar2) = 0; # coupe local_98 avec un '\0' à iVar2 (argv[1])
    fread(local_56,1,0x41,local_14);
    fclose(local_14);
    iVar2 = strcmp((char *)local_98,*(char **)(param_2 + 4)); # compare le contenu de local_98 (.pass avec un '\0' a iVar2) avec argv[1]

    # si la comparaison est correcte execute un shell
    if (iVar2 == 0) {
      execl("/bin/sh","sh",0);
    }
    else {
      puts(local_56);
    }
    uVar1 = 0;
  }
  return uVar1;
}
```

Avec une string vide le programme va exécuter le Shell car `atoi` va retourner `0` , puis le programme va couper `local_98` a l’index `0`  ce qui rend `local_98` vide donc au moment de la comparaison entre `local_98` et `argv[1]`  `strcmp` va retourner `0` car les deux string sont vides

```bash
$ ./bonus3 ""
$ cat /home/user/end/.pass
3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c
```

FLAG: `3321b6f81659f9a71c76616f606e4b50189cecfea611393d5d649f75e157353c`
