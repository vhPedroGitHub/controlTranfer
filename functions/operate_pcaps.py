from scapy.all import IP, TCP
from scapy.sessions import TCPSession
from classes.capture_pcap import CapturePcap
from functions.other_functions import eliminar_contenido_en_directorio
import os
from variables.init_vars import limit
import logging
from threading import Lock

loggers = {}
log_file_path = f"archives/logs"

def setup_logger(log_file_path, pod_name):
    # Crear el archivo de log específico para el pod
    log_file = f"{log_file_path}"
    # Crear un logger específico para el pod
    logger = logging.getLogger(pod_name)
    logger.setLevel(logging.INFO)  # Nivel de logging

    # Crear un handler para escribir en el archivo
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)

    # Formato del log
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(formatter)

    # Agregar el handler al logger
    logger.addHandler(file_handler)

    return logger

pcaps_conf = CapturePcap.from_directory("archives/tcpdump_files", limit)

def get_packets(pcap_conf):
    print(f"Obteniendo paquetes de {pcap_conf.pod_name}")
    packets = pcap_conf
    loggers[pcap_conf.pod_name] = setup_logger(f"{log_file_path}/{pcap_conf.pod_name}.log", pcap_conf.pod_name)
    return [packets, pcap_conf.pod_name]

def get_all_packets(pcaps_conf):
    print("Obteniendo todos los paquetes")
    all_packets = []
    for pcap in pcaps_conf:
        all_packets.append(get_packets(pcap))
    return all_packets

# Crear un Lock global para sincronizar la escritura en el archivo
file_lock = Lock()

def generate_txt_packets(packets, pod_name, filename):
    print(f"Generando archivo de texto para {pod_name}")
    
    # Asegurarse de que el directorio existe
    os.makedirs(filename, exist_ok=True)
    
    # Ruta completa del archivo
    file_path = os.path.join(filename, f"{pod_name}.txt")
    
    # Usar un Lock para evitar condiciones de carrera
    with file_lock:
        with open(file_path, 'w') as f:
            try:
                for packet in packets.capture:
                    if packet:  # Verificar que el paquete no esté vacío
                        f.write(str(packet.summary()) + '\n')
                packets.reset_lecture()
            except: 
                for packet in packets:
                    if packet:
                        f.write(str(packet.summary()) + '\n')

def write_string_to_file(string, pod_name, filename):
    print(f"Escribiendo en el archivo {pod_name}.txt")
    with file_lock:
        with open(f'{filename}/{pod_name}.txt', 'w') as f:
            f.write(string)

def split_long_lines(text, max_length=80):
    return "\n".join([text[i:i+max_length] for i in range(0, len(text), max_length)])

def build_tcp_flow(packets, pod_name, filename):
    # Agrupar paquetes por sesión TCP
    sessions = packets.capture.sessions(session_extractor=TCPSession)
    # input("Press Enter to continue...")

    # Diccionario para almacenar los datos de cada sesión TCP
    tcp_flows = {}

    for session in sessions:
        # Lista para almacenar los paquetes ordenados por número de secuencia
        ordered_packets = []

        for pkt in sessions[session]:
            if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                # Extraer el número de secuencia TCP
                seq_num = pkt[TCP].seq
                # Extraer el payload (datos brutos)
                payload = pkt["Raw"].load
                # Guardar el paquete con su número de secuencia
                ordered_packets.append((seq_num, payload))

        # Ordenar los paquetes por número de secuencia
        ordered_packets.sort(key=lambda x: x[0])

        # Reconstruir el flujo de datos TCP en orden
        flow = b""
        for seq_num, payload in ordered_packets:
            flow += payload

        # Guardar el flujo de datos en el diccionario
        tcp_flows[session] = flow

    # Crear la carpeta si no existe
    if not os.path.exists(f"{filename}/{pod_name}"):
        os.makedirs(f"{filename}/{pod_name}")

    with file_lock:
        # Guardar todos los flujos en un solo archivo .txt
        with open(f"{filename}/{pod_name}/all_sessions.txt", "w", encoding="utf-8") as f:
            for i, (session, flow) in enumerate(tcp_flows.items()):
                if flow != b"":
                    # Extraer información de la sesión (IP y puertos)
                    # Acceder a la capa IP y TCP del primer paquete de la sesión
                    first_packet = sessions[session][0]
                    if first_packet.haslayer(IP) and first_packet.haslayer(TCP):
                        src_ip = first_packet[IP].src
                        dst_ip = first_packet[IP].dst
                        src_port = first_packet[TCP].sport
                        dst_port = first_packet[TCP].dport
                    else:
                        # Si no hay capa IP o TCP, usar valores por defecto
                        src_ip, src_port, dst_ip, dst_port = "Unknown", 0, "Unknown", 0
                    # Decodificar el flujo binario a una cadena de texto (UTF-8)
                    decoded_text = flow.decode("utf-8", errors="ignore")

                    # Dividir el texto en líneas más cortas
                    formatted_text = split_long_lines(decoded_text)

                    # Escribir la información de la sesión en el archivo
                    f.write(f"=== Sesión {i + 1} ===\n")
                    f.write(f"ID de sesión: {session}\n")
                    f.write(f"Origen: {src_ip}:{src_port}\n")
                    f.write(f"Destino: {dst_ip}:{dst_port}\n")
                    f.write(f"Datos:\n{formatted_text}\n\n")

        # Guardar todos los flujos en un solo archivo .bin
        with open(f"{filename}/{pod_name}/all_sessions.bin", "wb") as f:
            for i, (session, flow) in enumerate(tcp_flows.items()):
                if flow != b"":
                    # Escribir la información de la sesión en el archivo binario
                    session_info = f"=== Sesión {i + 1} ===\nID de sesión: {session}\n".encode("utf-8")
                    f.write(session_info)
                    # Convertir el flujo a hexadecimal y escribirlo en el archivo
                    hex_flow = flow.hex().encode("utf-8")
                    f.write(hex_flow)
                    f.write(b"\n\n")

    packets.reset_lecture()
    return tcp_flows

def format_dict_src_dst(dict_src_dst):
    formatted = "\n".join([f"{src} : {dst}" for src, dst in dict_src_dst.items()])
    return formatted


def anal_pcap(packets, pod_name, filename, filename_tcp, pods_dict):
    print(f"Analizando pcap de {pod_name}")
    count = 0
    for i in packets.capture:
        count += 1

    packets.reset_lecture()
        
    stats = {
        "total_packets": count,
        "protocols": {}
    }

    dict_src_dst = {}
    for packet in packets.capture:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            src_name = f"{pods_dict.get(src_ip, src_ip)}"
            dst_name = f"{pods_dict.get(dst_ip, dst_ip)}"

            src_dst = f"{src_name} ----> {dst_name}"

            if src_dst in dict_src_dst:
                dict_src_dst[src_dst] += 1
            else: 
                dict_src_dst[src_dst] = 1

        layers = packet.layers()
        for layer in layers:
            proto_name = layer.__name__
            if proto_name in stats["protocols"]:
                stats["protocols"][proto_name] += 1
            else:
                stats["protocols"][proto_name] = 1
    
    packets.reset_lecture()

    write_string_to_file(f'''
Statistics for {pod_name}:


Protocols: {stats['protocols']}


src --> dst:

{format_dict_src_dst(dict_src_dst)}
                         '''
                            , pod_name, filename)
    
    if stats["protocols"] != {} and ("tcp" in stats["protocols"] or "TCP" in stats["protocols"]):
        build_tcp_flow(packets, pod_name, filename_tcp)