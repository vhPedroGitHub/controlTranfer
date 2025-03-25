from scapy.all import IP
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pyvis.network import Network
from functions.operate_pcaps import get_all_packets
from functions.operate_pcaps import generate_txt_packets
from functions.operate_pcaps import anal_pcap, loggers
import os

aris_color = 'blue'
node_size = 1000
radianes = 0.1
font_size = 10
arrowstyle = '->'
arrows = True
arrowsize = 15

def create_graph_dynamic_html(pod_name, G):
    print(f"Creando grafo dinámico para el pod: {pod_name}")
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
    net.show(html_filename)

    print(f"Grafo dinámico guardado en: {html_filename}")

def add_arcs(packets, G, pods_dict, pod_name, services_dict_name_port={}):
    # Ruta del archivo de log
    logger = loggers[pod_name]
    print(f"Agregando aristas al grafo")
    i = 0
    # Agregar aristas al grafo
    if services_dict_name_port != {}:
        for packet in packets.capture:
                src_port = packet[IP].sport
                dst_port = packet[IP].dport
                print(dst_port, src_port, pod_name)
                logger.info(f"{dst_port}, {src_port}")

                src_name = f"{services_dict_name_port.get(src_port, src_port)}"
                dst_name = f"{services_dict_name_port.get(dst_port, dst_port)}"
                G.add_edge(src_name, dst_name, color=aris_color)

                i += 1

                if i % 1000 == 0:
                    print(f"Paquete {i} +++++ {pod_name}")
                    logger.info(f"Paquete {i}")

                    if i % 100000:
                        pos = save_graph(G)

                        # Dibujar aristas curvas
                        draw_arcs(G, pos)
                        
                        plt.savefig(f'archives/imgs/pods_traffic/{pod_name}.png')
                        plt.close()

                        create_graph_dynamic_html(pod_name, G)
    else:
        for packet in packets.capture:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                logger.info(f"{src_ip}, {dst_ip}")
                
                src_name = f"{pods_dict.get(src_ip, src_ip)}"
                dst_name = f"{pods_dict.get(dst_ip, dst_ip)}"
                G.add_edge(src_name, dst_name, color=aris_color)

                i += 1
                if i % 1000 == 0:
                    print(f"Paquete {i} +++++ {pod_name}")
                    logger.info(f"Paquete {i}")

                    if i % 100000 == 0:
                        pos = save_graph(G)

                        # Dibujar aristas curvas
                        draw_arcs(G, pos)
                        
                        plt.savefig(f'archives/imgs/pods_traffic/{pod_name}.png')
                        plt.close()

                        create_graph_dynamic_html(pod_name, G)

    packets.reset_lecture()

def add_arcs_per_second(packets, G, pods_dict):
    # Agregar aristas al grafo
    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            src_name = f"{pods_dict.get(src_ip, src_ip)}"
            dst_name = f"{pods_dict.get(dst_ip, dst_ip)}"
            G.add_edge(src_name, dst_name, color=aris_color)


def save_graph(G, node_size=node_size, font_size=font_size):
    print(f"Guardando el grafo")
    # Guardar el grafo final como una imagen
    pos = nx.spring_layout(G)
    plt.figure(figsize=(12, 8))
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=node_size)
    nx.draw_networkx_labels(G, pos, font_size=font_size)

    return pos

def draw_arcs(G, pos, radianes=radianes, arrows=arrows, arrowstyle=arrowstyle, arrowsize=arrowsize, node_size=node_size):
    print(f"Dibujando aristas")
    # Dibujar aristas curvas
    for u, v, data in G.edges(data=True):
        rad = radianes  # Ajustar la curvatura según la clave de la arista
        nx.draw_networkx_edges(
            G, pos, edgelist=[(u, v)], 
            edge_color=data['color'], 
            arrowstyle=arrowstyle,  # Estilo de la punta de flecha
            arrows=arrows,  # Habilitar las puntas de flecha
            arrowsize=arrowsize,  # Aumentar el tamaño de las flechas
            node_size=node_size,  # Ajustar el tamaño de los nodos para que las flechas no se oculten
            connectionstyle=f"arc3,rad={rad}"  # Hacer las aristas curvas
        )


# Función para crear un grafo a partir de los paquetes
def create_graph(packets, pod_name, pods_dict, services_dict_name_port={}):
    print(f"Creando grafo para el pod: {pod_name}")
    G = nx.DiGraph()

    add_arcs(packets, G, pods_dict, pod_name, services_dict_name_port)
    pos = save_graph(G)

    # Dibujar aristas curvas
    draw_arcs(G, pos)
    
    plt.savefig(f'archives/imgs/pods_traffic/{pod_name}.png')
    plt.close()

    create_graph_dynamic_html(pod_name, G)
    
    generate_txt_packets(packets, pod_name, "archives/tcpdumps/pods_traffic", pods_dict)
    anal_pcap(packets, pod_name, "archives/tcpdumps/statistics_pods_traffic", "archives/tcpdumps/content_tcp", pods_dict)

def create_graph_using_all_pcaps(pods_dict, pcaps_conf, services_dict_name_port={}):
    print(f"Creando grafo para todos los pods")
    all_packets = get_all_packets(pcaps_conf)
    G = nx.DiGraph()
    for packets, pod_name in all_packets:

        add_arcs(packets, G, pods_dict, pod_name, services_dict_name_port)
        pos = save_graph(G, node_size=500)

        # Dibujar aristas curvas
        draw_arcs(G, pos, node_size=500)
        
    plt.savefig(f'archives/imgs/pods_traffic/all.png')
    plt.close()

    create_graph_dynamic_html("all", G)

def create_all_graph(pods_dict, pcaps_conf, services_dict_name_port={}):
    print(f"Creando grafo para todos los pods")
    all_packets = get_all_packets(pcaps_conf)
    for packets, pod_name in all_packets:
        create_graph(packets, pod_name, pods_dict, services_dict_name_port)
    create_graph_using_all_pcaps(pods_dict, pcaps_conf, services_dict_name_port)


def create_graph_per_second(packets, pods_dict, output_folder="archives/imgs/pods_traffic/image_persecond", seconds=1):
    print(f"Generando imágenes de tráfico por segundo")
    
    G = nx.DiGraph()
    last_timestamp = None
    counter = 0  # Para nombrar las imágenes de forma secuencial

    # Asegurar que la carpeta de salida existe
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        os.makedirs(f"{output_folder}/traffic")

    packs = []

    for packet in packets:
        if not hasattr(packet, 'time'):
            continue  # Si el paquete no tiene un campo de tiempo, lo ignoramos

        current_time = packet.time

        # Si es el primer paquete, inicializamos last_timestamp
        if last_timestamp is None:
            last_timestamp = current_time

        # Solo actualizamos el grafo si ha pasado 1 segundo desde la última imagen generada
        if current_time - last_timestamp >= seconds:
            last_timestamp = current_time
            counter += seconds  # Incrementar el contador para generar nombres de archivo únicos
            
            # Agregar los arcos correspondientes al grafo
            add_arcs_per_second(packs, G, pods_dict)
            pos = save_graph(G)

            # Dibujar aristas curvas
            draw_arcs(G, pos)

            # Guardar la imagen con un nombre único
            image_path = os.path.join(output_folder, f"segundo-{counter}.png")
            plt.savefig(image_path)
            plt.close()
            print(f"Imagen guardada: {image_path}")

            generate_txt_packets(packs, f"segundo-{counter}", f"{output_folder}/traffic", pods_dict)

            # Limpiar la lista de paquetes
            packs = []
            G.clear()

        packs.append(packet)

    print("Proceso completado.")

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
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=node_size, ax=ax)
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
            G.add_edge(src_ip, dst_ip, color=aris_color)

        # Configurar la figura y el eje
        fig, ax = plt.subplots()

        # Bucle para avanzar la animación con Enter
        frame = 0
        while frame < len(connections):
            update_graph(frame, G, connections, ax)
            plt.pause(0.1)  # Pausa para mostrar el gráfico
            input("Presiona Enter para ver el siguiente paquete...")  # Esperar a que se presione Enter
            frame += 1