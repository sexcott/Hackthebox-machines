## Tecnicas utilizadas
- ElasticSearch Enumeration
- Information Leakage
- Kibana Enumeration
- Kibana Exploitation (CVE-2018-17246)
- Abusing Logstash (Privilege Escalation)
## Procedimiento
- Fuzzing
- Forense a la Imagen(*Strings, Steghide, Exiftool*)
- Enumerar el ElasticSearch con el material que nos brinda HackTricks.
- Filtrar por palabras interesantes en la query.
- Nos conectamos por SSH con las credenciales encontradas.
- Aprovechamos el LFI que tiene la versión que se esta utilizando de Kibana para generar una Revere shell como el usuario *Kibana*.
- Spawneamos una tty con python ``python -c 'import pty;pty.spawn("/bin/bash")'``
- Filtramos por archivos que nos pertenezcan e inspeccionamos las rutas y archivos.
