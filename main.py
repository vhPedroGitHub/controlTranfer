# obteniendo una lista de pods con los datos que nos interesan
from concurrent.futures import ProcessPoolExecutor
from functions.other_functions import eliminar_contenido_en_directorio
from functions.analize_traces import search_packet_share
from functions.analize_traces import analyze_multiple_pcaps
from functions.analize_traces import consolidate_packets_by_time
from functions.operate_pcaps import generate_txt_packets
from functions.analize_grpc_packets import process_pcap_grpc, process_pcap_grpc_scapy
from functions.paralelize import *
from variables.init_vars import *

from functions.get_new_pcaps import get_new_pcaps
get_new_pcaps(pods_list, v1, ping, curl)

from functions.visualize_pcaps import create_all_graph
from functions.operate_pcaps import pcaps_conf
print(services_dict_name_port)
print(pcaps_conf)

# eliminamos los archivos existentes
eliminar_contenido_en_directorio("archives/tcpdumps/pods_traffic")
eliminar_contenido_en_directorio("archives/tcpdumps/statistics_pods_traffic")
eliminar_contenido_en_directorio("archives/tcpdumps/content_tcp")
eliminar_contenido_en_directorio("archives/logs")
eliminar_contenido_en_directorio("archives/imgs/dinamic_html")
eliminar_contenido_en_directorio("archives/imgs/pods_traffic")

if turbo:
    process_all_pcaps(pcaps_conf, pods_dict, services_dict_name_port)

else:
    create_all_graph(pods_dict, pcaps_conf, services_dict_name_port)

# Comparar los archivos PCAP
consolidate_packets = analyze_multiple_pcaps(pcaps_conf, seePerSecond)





