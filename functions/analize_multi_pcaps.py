from scapy.all import IP, TCP
from functions.visualize_pcaps import create_graph_per_second
from functions.write_pcaps import *
from functions.operate_pcaps import consolidate_packets, consolidate_packets_with_payload, get_all_packets_v2

from scapy.all import IP, TCP, Raw

from datetime import datetime
def analyze_multiple_pcaps(pcaps_conf, seePerSecond, pods_dict, createVideos=False):
    """
    Analiza múltiples archivos PCAP y organiza el tráfico según la fecha y hora en que ocurrió.

    :param pcaps_conf: Lista de objetos PCAP con capacidad de lectura.
    :param seePerSecond: Booleano para determinar si generar gráficos por segundo.
    :param pods_dict: Diccionario con información de pods.
    :return: Diccionario con paquetes organizados.
    """
    all_packets = []
    
    dict_packets_to_analize = {
        "packets_sumary": [],
        "all_packets": [],
        "only_payloads": []
    }

    for file in pcaps_conf:
        file.reset_lecture()
        packets = file.capture
        
        for packet in packets:
            try:
                # Verificar que sea paquete TCP/IP válido
                if not (packet.haslayer(IP) and packet.haslayer(TCP)):
                    continue
                
                # Manejo robusto del timestamp
                if hasattr(packet, 'time'):
                    try:
                        timestamp = datetime.fromtimestamp(float(packet.time))
                        all_packets.append((timestamp, packet))
                    except (ValueError, TypeError) as e:
                        print(f"Error con timestamp en paquete: {e}")
                        timestamp = datetime.now()  # Usar hora actual como fallback                
            except Exception as e:
                print(f"Error procesando paquete: {e}")
                continue
        
        file.reset_lecture()

    # Ordenar paquetes por timestamp
    all_packets.sort(key=lambda x: x[0])

    # Procesar los paquetes
    dict_packets_to_analize["packets_sumary"] = consolidate_packets(all_packets, 0)
    dict_packets_to_analize["all_packets"] = get_all_packets_v2(all_packets, 1)
    dict_packets_to_analize["only_payloads"] = consolidate_packets_with_payload(all_packets, 2)

    if seePerSecond:
        create_graph_per_second(pods_dict, dict_packets_to_analize, createVideos=createVideos)

def search_packet_share(pcap_origin, pcap_dest):
    """
    Busca si un paquete de un archivo PCAP (origen) fue reenviado por el servicio del otro PCAP (destino).
    
    :param pcap_origin: Lista de paquetes del PCAP de origen.
    :param pcap_dest: Lista de paquetes del PCAP de destino.
    :return: Lista de tuplas (paquete_origen, ip_destino_reenvio) que fueron reenviados.
    """
    # Crear una lista para almacenar los paquetes reenviados y sus destinos
    packets_share = []

    pcap_origin.reset_lecture()
    pcap_dest.reset_lecture()

    print(pcap_dest, pcap_origin)
    print(pcap_origin.capture)
    print(pcap_dest.capture)

    # Extraer firmas únicas de los paquetes del destino
    firms_dest = {}
    for packet in pcap_dest.capture:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            firma = (
                packet[IP].src,  # IP origen del paquete en el destino
                packet[TCP].sport,  # Puerto origen del paquete en el destino
                packet[TCP].seq   # Número de secuencia TCP
            )
            firms_dest[firma] = packet[IP].dst  # Guardar la IP destino del paquete en el destino

    # Buscar coincidencias entre paquetes de origen y destino
    for packet in pcap_origin.capture:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            firma = (
                packet[IP].dst,  # IP destino del paquete en el origen
                packet[TCP].dport,  # Puerto destino del paquete en el origen
                packet[TCP].seq   # Número de secuencia TCP
            )
            if firma in firms_dest:
                ip_reenvio = firms_dest[firma]
                if ip_reenvio != packet[IP].src:  # Verificar que fue enviado a una IP distinta
                    packets_share.append((packet, ip_reenvio))

    return packets_share