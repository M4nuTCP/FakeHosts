from scapy.all import *
import random
import netifaces
import signal

def generate_random_ip(network_range):
    subnet = network_range.split('.')[:-1]
    ip = '.'.join(subnet) + '.' + str(random.randint(1, 254))
    return ip

def fakepacket(packet, simulated_ips, mac_address):
    if packet[ARP].op == 1: 
        if packet.pdst in simulated_ips:
            print(f"Dirección IP manipulada: {packet.pdst}")
            reply = ARP(op=2,
                        hwsrc="00:20:91:da:eb:69",  
                        psrc=packet.pdst,  
                        hwdst=mac_address, 
                        pdst=packet.pdst)  
            pkt = Ether(dst=mac_address, src="00:20:91:da:eb:69") / reply
            sendp(pkt, iface="eth0")

def signal_handler(sig, frame):
    print('Interrupción recibida, cerrando...')
    sys.exit(0)

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)

    network_range = input("[+] Ingresa el rango de la red (por ejemplo, 192.168.20.0): ")
    cantidad_ips = int(input("[+] Cantidad de IPs a Simular: "))
    mac_address = input("[+] Ingresa la dirección MAC de destino (recomendada: tu máquina actual o la de una existente en la trama de red): ")

    simulated_ips = []
    for _ in range(cantidad_ips):
        while True:
            ip = generate_random_ip(network_range)
            if ip not in simulated_ips:
                simulated_ips.append(ip)
                break
    
    print(f"IPs simuladas: {simulated_ips}")

    sniff(iface="eth0", filter="arp", prn=lambda x: fakepacket(x, simulated_ips, mac_address))
