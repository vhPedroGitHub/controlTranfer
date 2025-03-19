from scapy.all import IP
# from datetime import datetime
import networkx as nx
import matplotlib.pyplot as plt
# import sqlite3
import time
from decimal import Decimal
from classes.capture_pcap import CapturePcap
from pyvis.network import Network

pcaps_conf = CapturePcap.from_directory("archives/tcpdump_files")

def get_packets(pcap_conf):
    packets = pcap_conf.capture
    for pcap in packets:
        if IP in pcap:
            print(pcap)
    return [packets, pcap_conf.pod_name]

def get_all_packets(pcaps_conf):
    all_packets = []
    for pcap in pcaps_conf:
        all_packets.append(get_packets(pcap))
    return all_packets

def generate_txt_packets(packets, pod_name):
    with open(f'archives/tcpdumps/pods_traffic/{pod_name}.txt', 'w') as f:
        for packet in packets:
            if IP in packet:
                f.write(str(packet) + '\n')

def create_graph_dynamic_html(pod_name, G):
    # Crear un grafo de PyVis
    net = Network(notebook=True, directed=True, cdn_resources='remote')

    # Agregar nodos y aristas desde el grafo de NetworkX
    for node in G.nodes:
        net.add_node(node)

    for edge in G.edges(data=True):
        src, dst, data = edge
        net.add_edge(src, dst)

    # Guardar el grafo como un archivo HTML
    html_filename = f'archives/imgs/dinamic_html/{pod_name}.html'

    # Guardar y mostrar el grafo en un navegador
    net.show(html_filename, notebook=False)

    print(f"Grafo dinámico guardado en: {html_filename}")

# Función para crear un grafo a partir de los paquetes
def create_graph(packets, pod_name, pods_dict):
    G = nx.DiGraph()
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_name = pods_dict.get(src_ip, src_ip)
            dst_name = pods_dict.get(dst_ip, dst_ip)
            G.add_edge(src_name, dst_name, color='blue')
    # Guardar el grafo final como una imagen
    pos = nx.spring_layout(G)
    plt.figure(figsize=(12, 8))
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=1000)
    nx.draw_networkx_labels(G, pos, font_size=10)

    # Dibujar aristas curvas
    for u, v, data in G.edges(data=True):
        rad = 0.1  # Ajustar la curvatura según la clave de la arista
        nx.draw_networkx_edges(
            G, pos, edgelist=[(u, v)], 
            edge_color=data['color'], 
            arrowstyle='->',  # Estilo de la punta de flecha
            arrows=True,  # Habilitar las puntas de flecha
            arrowsize=15,  # Aumentar el tamaño de las flechas
            node_size=1000,  # Ajustar el tamaño de los nodos para que las flechas no se oculten
            connectionstyle=f"arc3,rad={rad}"  # Hacer las aristas curvas
        )
    
    plt.savefig(f'archives/imgs/pods_traffic/{pod_name}.png')
    plt.close()

    create_graph_dynamic_html(pod_name, G)

    generate_txt_packets(packets, pod_name)


def create_all_graph(pods_dict):
    all_packets = get_all_packets(pcaps_conf)
    for packets, pod_name in all_packets:
        create_graph(packets, pod_name, pods_dict)

# funciones animadas
# Función para actualizar el grafo en cada fotograma
def update_graph(frame, G, connections, ax):
    ax.clear()  # Limpiar el eje

    # Cambiar el color de la arista correspondiente al paquete actual

    src_ip, dst_ip = connections[frame]
    G[src_ip][dst_ip]['color'] = 'green'  # Cambiar a verde

    # Dibujar el grafo
    if frame == 0:
        global pos
        pos = nx.spring_layout(G)  # Posición de los nodos solo en el primer frame
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=1000, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=5, ax=ax)

    # Dibujar aristas curvas
    for u, v, data in G.edges(data=True):
        rad = 0.1 # Ajustar la curvatura según la clave de la arista
        nx.draw_networkx_edges(
            G, pos, edgelist=[(u, v)], 
            edge_color=data['color'], 
            arrowstyle='->',  # Estilo de la punta de flecha
            arrows=True,  # Habilitar las puntas de flecha
            arrowsize=15,  # Aumentar el tamaño de las flechas
            node_size=1000,  # Ajustar el tamaño de los nodos para que las flechas no se oculten
            connectionstyle=f"arc3,rad={rad}",  # Hacer las aristas curvas
            ax=ax
        )

    # Restaurar el color de la arista a azul después de mostrarla
    G[src_ip][dst_ip]['color'] = 'blue'

    # Mostrar el número de paquete
    ax.set_title(f"Paquete {frame + 1} de {len(connections)}")

def operate_pcap(pods_dict, packets):
    if input("¿Desea cargar los archivos .pcap? (s/n): ").strip().lower() == 's':
        G = nx.DiGraph()
        # Extraer las direcciones IP de origen y destino
        connections = []
        for packet in packets:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_name = pods_dict.get(src_ip, src_ip)
                dst_name = pods_dict.get(dst_ip, dst_ip)
                connections.append((src_name, dst_name))

        # Agregar todas las conexiones al grafo
        for src_ip, dst_ip in connections:
            G.add_edge(src_ip, dst_ip, color='blue')

        # Configurar la figura y el eje
        fig, ax = plt.subplots()

        # Bucle para avanzar la animación con Enter
        frame = 0
        while frame < len(connections):
            update_graph(frame, G, connections, ax)
            plt.pause(0.1)  # Pausa para mostrar el gráfico
            input("Presiona Enter para ver el siguiente paquete...")  # Esperar a que se presione Enter
            frame += 1