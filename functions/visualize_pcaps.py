from scapy.all import IP, Raw
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pyvis.network import Network
from functions.operate_pcaps import get_all_packets
from functions.write_pcaps import generate_txt_packets
from functions.operate_pcaps import anal_pcap, loggers, generate_timemaps_packets
from matplotlib.animation import FuncAnimation
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

def generate_video_traffic(packets, pods_dict, output_file):
    """
    Genera un video que muestra el tráfico entre nodos, resaltando el paquete activo en cada momento.
    
    :param packets: Lista de tuplas (timestamp, packet) ordenadas cronológicamente
    :param pods_dict: Diccionario {ip: {'name': pod_name}}
    :param output_file: Ruta del archivo de salida
    """
    # 1. Validación de entrada
    if not packets:
        print("La lista de paquetes está vacía")
        return 0 
    
    # 2. Crear grafo y nodos basados en tráfico real
    G = nx.DiGraph()
    active_pods = set()

    packets_new = []
    packets_new = generate_timemaps_packets(packets)

    if packets_new == []:
        return 0

    # Procesar todos los paquetes para identificar nodos activos
    for timestamp, packet in packets_new:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if src_ip in pods_dict and dst_ip in pods_dict:
                src_name = pods_dict[src_ip]
                dst_name = pods_dict[dst_ip]

                G.add_edge(src_name, dst_name)
                active_pods.update([src_name, dst_name])

    # Añadir nodos al grafo
    for pod in active_pods:
        G.add_node(pod, color='lightblue', size=1000)
    
    # 3. Configuración de la figura
    fig, ax = plt.subplots(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42)  # Posiciones fijas para consistencia
    
    # 4. Función de animación mejorada
    def update(frame):
        ax.clear()
        
        # Calcular tiempo actual (0-100% de la duración total)
        total_duration = packets_new[-1][0] - packets_new[0][0]
        current_time = packets_new[0][0] + total_duration * (frame / 100)
        
        # Buscar el paquete más cercano a este tiempo
        active_packet = None
        min_diff = float('inf')
        
        for timestamp, packet in packets_new:
            time_diff = abs((timestamp - current_time).total_seconds())
            if time_diff < min_diff and IP in packet:
                min_diff = time_diff
                active_packet = packet
        
        # Preparar atributos visuales
        edge_colors = []
        edge_widths = []
        node_colors = []
        
        # Inicializar todos como inactivos
        for _ in G.edges():
            edge_colors.append('lightgray')
            edge_widths.append(1)
        
        for _ in G.nodes():
            node_colors.append('lightblue')
        
        # Resaltar el paquete activo
        if active_packet and active_packet[IP].src in pods_dict and active_packet[IP].dst in pods_dict:
            src_name = pods_dict[active_packet[IP].src]
            dst_name = pods_dict[active_packet[IP].dst]
            
            # Buscar índice de la arista activa
            edges = list(G.edges())
            if (src_name, dst_name) in edges:
                idx = edges.index((src_name, dst_name))
                edge_colors[idx] = 'red' if active_packet.haslayer(Raw) else 'blue'
                edge_widths[idx] = 4
                
                # Resaltar nodos involucrados
                node_indices = list(G.nodes())
                src_idx = node_indices.index(src_name)
                dst_idx = node_indices.index(dst_name)
                node_colors[src_idx] = 'orange'
                node_colors[dst_idx] = 'green'
        
        # Dibujar el grafo
        nx.draw_networkx_nodes(
            G, pos, 
            node_color=node_colors,
            node_size=[G.nodes[n]['size'] for n in G.nodes()],
            ax=ax
        )
        
        nx.draw_networkx_edges(
            G, pos,
            edgelist=list(G.edges()),  # Asegurar que dibuja todas las aristas
            edge_color=edge_colors,
            width=edge_widths,
            arrows=True,
            arrowstyle='->',
            arrowsize=20,
            ax=ax
        )
        
        nx.draw_networkx_labels(
            G, pos,
            font_size=10,
            font_weight='bold',
            ax=ax
        )
        
        # Añadir información temporal
        ax.set_title(
            f"Tráfico en tiempo: {current_time.strftime('%H:%M:%S.%f')[:-3]}\n"
            f"Paquete: {'Con payload' if active_packet and active_packet.haslayer(Raw) else 'De control' if active_packet else 'N/A'}",
            fontsize=12
        )
    
    # 5. Configuración de la animación
    try:
        ani = FuncAnimation(
            fig, update, 
            frames=100, 
            interval=100,
            blit=False
        )
        
        # Configurar FFmpeg
        plt.rcParams['animation.ffmpeg_path'] = '/usr/bin/ffmpeg'
        
        # Guardar el video
        ani.save(
            output_file,
            writer='ffmpeg',
            fps=10,
            dpi=150,
            extra_args=['-vcodec', 'libx264']
        )
        print(f"✅ Video guardado exitosamente en {output_file}")
        
    except Exception as e:
        print(f"❌ Error al generar el video: {e}")
        # Fallback: guardar imagen estática
        update(50)  # Frame del medio
        plt.savefig(output_file.replace('.mp4', '.png'))
        print(f"🖼️ Se guardó imagen estática en {output_file.replace('.mp4', '.png')}")
    
    plt.close()

# Función para crear un grafo a partir de los paquetes
def create_graph(packets, pod_name, pods_dict, services_dict_name_port={}, createVideos=False):
    print(f"Creando grafo para el pod: {pod_name}")
    G = nx.DiGraph()

    add_arcs(packets, G, pods_dict, pod_name, services_dict_name_port)
    pos = save_graph(G)

    # Dibujar aristas curvas
    draw_arcs(G, pos)
    
    plt.savefig(f'archives/imgs/pods_traffic/{pod_name}.png')
    plt.close()

    create_graph_dynamic_html(pod_name, G)

    if not os.path.exists("archives/imgs/pods_traffic/video"):
        os.makedirs("archives/imgs/pods_traffic/video")
    
    generate_txt_packets(packets, pod_name, "archives/tcpdumps/pods_traffic", pods_dict)
    anal_pcap(packets, pod_name, "archives/tcpdumps/statistics_pods_traffic", "archives/tcpdumps/content_tcp", pods_dict)
    if createVideos:
        generate_video_traffic(packets, pods_dict, f"archives/imgs/pods_traffic/video/{pod_name}.mp4")

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

def create_all_graph(pods_dict, pcaps_conf, services_dict_name_port={}, createVideos=False):
    print(f"Creando grafo para todos los pods")
    all_packets = get_all_packets(pcaps_conf)
    for packets, pod_name in all_packets:
        create_graph(packets, pod_name, pods_dict, services_dict_name_port, createVideos)
    create_graph_using_all_pcaps(pods_dict, pcaps_conf, services_dict_name_port)

def for_in_packets(name_operation, pods_dict, packets, output_folder="archives/imgs/pods_traffic/image_persecond", seconds=1):
    packs = []

    G = nx.DiGraph()
    last_timestamp = None
    counter = 0  # Para nombrar las imágenes de forma secuencial

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

            if not os.path.exists(f"{output_folder}/segundo-{counter}"):
                os.makedirs(f"{output_folder}/segundo-{counter}")

            # Guardar la imagen con un nombre único
            image_path = os.path.join(f"{output_folder}/segundo-{counter}", f"segundo-{counter}-{name_operation}.png")
            plt.savefig(image_path)
            plt.close()
            print(f"Imagen guardada: {image_path}")

            if not os.path.exists(f"{output_folder}/00-traffic/segundo-{counter}"):
                os.makedirs(f"{output_folder}/00-traffic/segundo-{counter}")

            generate_txt_packets(packs, f"segundo-{counter}-{name_operation}", f"{output_folder}/00-traffic/segundo-{counter}", pods_dict)

            # Limpiar la lista de paquetes
            packs = []
            G.clear()

        packs.append(packet)

def create_graph_per_second(pods_dict, dict_packets_to_analize={}, output_folder="archives/imgs/pods_traffic/image_persecond", seconds=1):
    print(f"Generando imágenes de tráfico por segundo")
    
    # Asegurar que la carpeta de salida existe
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        os.makedirs(f"{output_folder}/00-traffic")

    for key, value in dict_packets_to_analize.items():
        for_in_packets(f"{key}", pods_dict, value, output_folder, seconds)

    print("Proceso completado.")