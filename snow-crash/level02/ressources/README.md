# level02

```bash
$ ls
level02.pcap

$ scp -P 4242 level02@192.168.179.131:/home/user/level02/level02.pcap .
$ chmod 777 level02.pcap
$ wireshark level02.pcap
```

Wireshark → Analyze → Follow → TCP Stream

```bash
Password: ft_wandr...NDRel.L0L
```

Each dot represents character 7f (DEL), giving the password: `ft_waNDReL0L`

```bash
$ su flag02
Password: ft_waNDReL0L
Don't forget to launch getflag !
$ getflag
Check flag.Here is your token : kooda2puivaav1idi4f57q8iq
```
