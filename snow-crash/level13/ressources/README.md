# level13

```lua
$ ls -l
total 8
-rwsr-sr-x 1 flag13 level13 7303 Aug 30  2015 level13
$ ./level13
UID 2013 started us but we we expect 4242
```

```lua
gdb level13
(gdb) b getuid
Breakpoint 1 at 0x8048380
(gdb) run
Starting program: /home/user/level13/level13

Breakpoint 1, 0xb7ee4cc0 in getuid () from /lib/i386-linux-gnu/libc.so.6
(gdb) step
Single stepping until exit from function getuid,
which has no line number information.
0x0804859a in main ()
(gdb) print $eax
$1 = 2013
(gdb) set $eax=4242
(gdb) step
Single stepping until exit from function main,
which has no line number information.
your token is 2A31L79asukciNyi8uppkEuSx
```
