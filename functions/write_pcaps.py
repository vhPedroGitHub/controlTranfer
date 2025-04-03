from scapy.all import IP
from functions.analize_errors import get_packet_errors
from functions.analize_a_packet import get_payload
import os
from threading import Lock
import datetime

# Crear un Lock global para sincronizar la escritura en el archivo
file_lock = Lock()

def generate_txt_packets(packets, pod_name, filename, pods_dict={}):
    print(f"Generando archivo de texto para {pod_name}")
    
    # Asegurarse de que el directorio existe
    os.makedirs(filename, exist_ok=True)
    
    # Ruta completa del archivo
    file_path = os.path.join(filename, f"{pod_name}.txt")
    
    # Usar un Lock para evitar condiciones de carrera
    with file_lock:
        with open(file_path, 'w') as f:
            try:
                for packet in packets:
                    errors = get_packet_errors(packet)
                    payload = get_payload(packet)
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        
                        src_name = f"{pods_dict.get(src_ip, src_ip)}"
                        dst_name = f"{pods_dict.get(dst_ip, dst_ip)}"
                        if packet:  # Verificar que el paquete no esté vacío
                            timestamp = packet.time
                            time = datetime.datetime.fromtimestamp(float(timestamp))
                            f.write(f"🚃source: {src_name}  ---->  dest: {dst_name} \n{time}\n - 🕵️{str(packet.summary())}\n ⚠️erros: {errors} \n payloads: {payload} \n\n")
                    else:
                        timestamp = packet.time
                        time = datetime.datetime.fromtimestamp(float(timestamp))
                        f.write(f"{time}\n - {str(packet.summary())}\n\n")
            except: 
                print("ocurrio un error")

def write_string_to_file(string, pod_name, filename):
    print(f"Escribiendo en el archivo {pod_name}.txt")
    with file_lock:
        with open(f'{filename}/{pod_name}.txt', 'w') as f:
            f.write(string)

def split_long_lines(text, max_length=80):
    return "\n".join([text[i:i+max_length] for i in range(0, len(text), max_length)])