--------
- Tags: #prototype-pollution #kubernetes #linux #peirates #pods #secrets-kubernetes #lfi #google-cloudstorage-commands
---------
## Tecnicas utilizadas

- Inspecting custom application  
- Code Analysis  
- Information Leakage  
- Local File Inclusion (LFI)  
- Google CloudStorage Commands Vulnerability (Command Injection) [RCE]  
- Prototype Pollution Exploitation (Granting us privileges)  
- Kubernetes (Interacting with the API) [kubectl]  
- Finding containers with kubectl  
- PIVOTING  
- Abusing Prototype Pollution to jump to another container  
- Listing secrets with kubectl  
- Creating malicious Pod (Privilege Escalation) [Bad Pods]  
- Peirates - Kubernetes Penetration Testing Tool [EXTRA]

## Procedimiento

![[Pasted image 20230614130033.png]]

El escaneo con nmap da como resultado los siguientes puertos:

![[Pasted image 20230614201359.png]]

Haciendo un whatweb podemos ver las tecnologias que corren por detras del servicio web:

![[Pasted image 20230614201428.png]]

--------------
#### Inspecting custom application  

En la pagina principal, vemos varios enlaces para descargar un *.zip* si descargamos el correspondiente para nuestro sistema operativo. Cuando lo descomprimimos, nos queda un *.deb*. Si le hacemos un **dpkg-deb** al archivo, nos va a descomprimir todo su contenido dentro de una carpeta indicada. Si buscamos por archivos ejecutables dentro de la carpeta, podemos ver que existe uno. Si intetamos correr el binario, nos lanza un programa con una grafica:

![[Pasted image 20230615000248.png]]

----------
#### Code Analysis 

Al iniciar, nos marca un error. Probablemente sea por que no tenemos contemplado el subdominio en el */etc/hosts* si lo colocamos y volvemos a inciar el programa podemos ver que ya no nos marca error. En la aplicacion existen diversos modulos, el ultimo muestra un comportamiento diferente, parece como si cargase algo cuando se le da click.

-----------
#### Information Leakage  

Si abrimos wireshark para ver que esta sucediendo en la aplicacion, podemos ver que la momento de clickear en el ultimo modulo se esta tramitando una peticion por post a *ToDo* en la cual estan viajando unas credenciales de autentificacion para una api.
Si tratamos de replicar la solicitud con **curl** podemos ver que nos muestra un mensaje.

----------
#### Local File Inclusion (LFI)  

Vemos que entre los campos de la data a tramitar hay  un llamado *filename*. Si intetamos un *lfi* vemos que no funciona, ni siquiera nos responde el servidor, si intentamos algo como un *path transversal* o un *bypass* no nos muestra nada.
Esto puede ser porque haya restricciones a nivel de palabras, si intetamos incluir en vez del */etc/passwd* un archivo que se encuentre en el mismo directorio podemos verlo claramente:



Si tratamos la data que alcabamos de conseguir, podemos ver el codigo mas legible. En el codigo hay un ruta *upload* a la que si tramitamos una peticion por post, nos retorna un *access denied*. Esto porque la subida de archivos esta solo disponible para el usuario *administrador*. Por otro lado, podemos ver que en el codigo se importa *Google CloudStorage Commands*. Si investigamos un poco por *google* podemos ver que existe una ejecución remota de comandos.

-------------
#### Google CloudStorage Commands

En el campo *Filename* podemos hacer una ejecucion remota de comandos, ya que inspeccionando el codigo en github de *Google CloudStorage Commands* vemos que no se sanitiza bien el input del *path*, asi que si colocamos un *&* o incluso un *;* podriamos colarle un comando a nivel de sistema.

Si lo intentamos, vemos que no podemos. Esto, denuevo por que no tenemos la capacidad de subida habilitada, eso es solo una capacidad una del usuario *admin*.

----------------
#### Prototype Pollution Exploitation (Granting us privileges) 

Vemos que en el codigo hay un *.merge* que a nivel de proto no esta sanitizado. Si buscamos en google por *.merge dangerous* podemos ver que hay muchos resultados donde se menciona el **prototype pollution**. 
Observando el codigo, vemos que el *.merge*  esta constituido por un mensaje y un cuerpo, esto hace referencia a la parte del *binario* donde se nos permitia mandar mensajes. Si capturamos el trafico con **wireshark** y mandamos un mensaje, podemos ver que se tramita una peticion por *PUT* donde a nivel de data se manda un campo *message* en vez de *filename*.

Si intentamos replicar la peticion con **curl** podemos ver que nos manda un mensaje que dice *"ok" : true*. Para acontecer el **Prototype Pollution**, podemos modificar el contenido del *message* a lo siguiente:

```js
"message":{"__proto__":{"canUpload":"true"}}
```

Una vez hecha la petición, podemos volver a intentar el **RCE** con el *Google CloudStorage Commands* y vemos que ahora si tenemos la capacidad de ejecutar los comandos.
00
---------------------
#### Kubernetes (Interacting with the API)

Una vez dentro de la maquina, si listamos por tareas cron, vemos que hay una:

Esta buscando por *kubectl* y lo esta eliminando cada minuto que pasa. Lo proximo a realizar, seria descargarnos el binario de *kubectl* de la pagina oficial, renombrarlo(para evitar que lo elimine la tarea cron) y subirlo. 
Una vez tenemos el *binario* en la maquina victima, podemos hacer un *./kubectl* para ver todas las opciones que tenemos.
Lo que nosotros haremos es ver que tenemos acceso hacer, de la siguiente manera:

	./kubectl auth

Posteriormente, podemos preguntarle cosas para ver si estamos autorizados para realizar. Un ejemplo serian los siguientes:

	./kubectl auth can-i get pods
	./kubectl auth can-i list pods
	./kubectl auth can-i list namespaces
	./kubectl auth can-i create pod

---------------
####  Finding containers with kubectl  

Como vemos, tenemos la capacidad de listar los *namespaces*, asi que si hacemos el siguiente comando, podremos listarlos:

	./kubectl get namespaces

Ahora, para listar los **pods** de los *namespaces* podemos hacer esto:

	./kubectl get pods -n <namespaces>

Una vez vemos los pods, podemos ver de manera mas detallada sus descripciones de la siguiente manera:

	-/kubectl describe pods/<pod> -n dev

#### PIVOTING  

Vemos que el contenedor desplegado, tiene la misma ip que la aplicacion corriendo del *binario*. Si lanzamos un curl, podemos ver lo que veiamos al principio en la aplicacion en el apartado de *Message Log*. Podriamos aprovecharnos de esto para hacer lo mismo que habiamos hecho con el **prototype pollution** para ejecutar comandos.

------------
#### Abusing Prototype Pollution to jump to another container

Volvemos a mandar el *message* con la inserción del **Prototype**, modificamos el campo para cambiar el atributo de *canUpload* a *true*. Podemos facilitar todo este trabajo si hacemos port fordwarding. Subimos chisel y nos pasamos el puerto y el sevidor que lo esta corriendo para tener alcance a el de manera local.

#### Listing secrets with kubectl  

Si volvemos a listar los privilegios que tenemos en kubectl, vemos que ahora nisiquiera tenemos la capacidad de listar los *namespaces*.
Pero como ya tenemos el conocimiento de los *namespaces* por el otro contenedor que habiamos comprometido, podemos ir directo a intentar listar los *secret* de los namespaces, podemos hacer lo siguiente para ver si tenemos la capacidad de listar los secretos:

	./kubectl auth can-i get secrets --all-namespaces

Vemos que en los secretos de un *namespaces* hay uno con nombre *c-admin-token* el cual llama la atencion, ya que, teniendo el token de un usuario administrador podemos crear un **pod**. Una vez obtenido el token, podemos hacer lo siguiente para crear el **pod**

	./kubectl describe secrets/<secret> -n <namespace>

Podemos dumpear el token del admin y posteriormente crear un **pod**. Tenemos que tomar el *.yml* malicioso encontrado en el repositorio *badPods/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml* para poder escalar a la maquina real.
Tenemos que modificar algunas cosas del archivo. podemos eliminar los campos de **labels**, los **hosts** tambien, menos el **hostNetwork**. La imagen la podemos sacar el **pod** del *namespaces* **dev**, si filtramos por *Image* podemos ver la ruta de la imagen. El **mountPath** lo cambiamos a **/root/** y el **name** tambien podemos cambiarlos.

Ahora, para ejecutar el **pod** con el **yaml** lo que tenemos que hacer es lo siguiente:

	./kubectl create -f reverse.yaml --token "<token>" 

Y ya deberiamos de tener nuestra reverse shell.

-----------
#### Peirates - Kubernetes Penetration Testing Tool [EXTRA]

En caso de que lo anterior no funcione, podemos usar **Peirates**. Descargamos el compilado y le hacemos un **gunzip**.
Lo trasladamos a la maquina victima y lo ejecutamos. Este nos automatiza todo, le tenemos que pasar el token con la flag *-f*