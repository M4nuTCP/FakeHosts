# FakeHosts

FakeHosts es una herramienta diseñada para simular múltiples IPs en una red, imitando máquinas de la NSA (o de cualquier otra organización configurable). Su propósito es dificultar los mapeos ARP dentro de la red, complicando así la tarea de los atacantes para mapear la red. La herramienta cubre únicamente los escaneos ARP. Se recomienda crear un servicio en una máquina dentro de la red y dejarlo funcionando.

# Documentación

📚Blog: https://m4nu.gitbook.io/m4nu/mis-proyectos/fakehosts

# POC:

![image](https://github.com/M4nuTCP/FakeHosts/assets/96147300/d48b2f82-7dca-4019-bbcf-c25ef3ccd436)

Si en la imagen anterior lo hubiéramos tomado en serio, habríamos configurado todas las MACs con el OUI de VMware para dificultar el mapeo de la red y la identificación de las verdaderas máquinas VMware.

# Cambio de OWI

```
def fakepacket(packet, simulated_ips, mac_address):
    if packet[ARP].op == 1: 
        if packet.pdst in simulated_ips:
            print(f"Dirección IP manipulada: {packet.pdst}")
            reply = ARP(op=2,
                        hwsrc="00:20:91:da:eb:69",  <- Cambiar la OUI de esta MAC
                        psrc=packet.pdst,  
                        hwdst=mac_address, 
                        pdst=packet.pdst)  
            pkt = Ether(dst=mac_address, src="00:20:91:da:eb:69") / reply   <- Cambiar la OUI de la mac "src"
            sendp(pkt, iface="eth0")
```

Para ver todas las OUI ejecute el siguiente comando:

```
macchanger -l
``` 
