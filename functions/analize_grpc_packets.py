import pyshark
from proto.server_pb2 import SctplbMessage, AmfMessage

from scapy.all import *
from scapy.all import TCP

def process_pcap_grpc(pcap_file):
    # Captura los paquetes SCTP del pcap
    capture = pyshark.FileCapture(
        pcap_file,
        display_filter='sctp.payload',  # Filtra solo paquetes SCTP con payload
        include_raw=True,
        use_json=True
    )
    
    for packet in capture:
        try:
            # Extrae el payload SCTP (capa de aplicación)
            if hasattr(packet, 'sctp'):
                payload = packet.sctp.payload.binary_value
                
                # Intenta parsear como SctplbMessage (AMF recibiendo)
                try:
                    sctp_msg = SctplbMessage()
                    sctp_msg.ParseFromString(payload)
                    print("\n=== Mensaje SCTPLB -> AMF ===")
                    print(f"Tipo: {sctp_msg.Msgtype}")
                    print(f"gNB ID: {sctp_msg.GnbId}")
                    print(f"IP gNB: {sctp_msg.GnbIpAddr}")
                    print(f"Mensaje: {sctp_msg.VerboseMsg}")
                    # Aquí puedes acceder a otros campos según necesites
                    continue
                except:
                    pass
                
                # Intenta parsear como AmfMessage (AMF enviando)
                try:
                    amf_msg = AmfMessage()
                    amf_msg.ParseFromString(payload)
                    print("\n=== Mensaje AMF -> SCTPLB ===")
                    print(f"Tipo: {amf_msg.Msgtype}")
                    print(f"AMF ID: {amf_msg.AmfId}")
                    print(f"gNB Destino: {amf_msg.GnbId}")
                    print(f"Redirección a: {amf_msg.RedirectId or 'N/A'}")
                    continue
                except:
                    pass
                
                print("\n=== Paquete no parseable ===")
                print(f"Payload hex: {payload.hex()}")
                
        except AttributeError as e:
            print(f"Error procesando paquete: {e}")
    
    capture.close()

def process_pcap_grpc_scapy(pcap_file):
    packets = rdpcap(pcap_file)
    for pkt in packets:
        if TCP in pkt:
            if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
                payload = pkt["Raw"].load
                # Procesar como en tu código original
                # Intenta parsear como SctplbMessage (AMF recibiendo)
                try:
                    sctp_msg = SctplbMessage()
                    sctp_msg.ParseFromString(payload)
                    print("\n=== Mensaje SCTPLB -> AMF ===")
                    print(f"Tipo: {sctp_msg.Msgtype}")
                    print(f"gNB ID: {sctp_msg.GnbId}")
                    print(f"IP gNB: {sctp_msg.GnbIpAddr}")
                    print(f"Mensaje: {sctp_msg.VerboseMsg}")
                    # Aquí puedes acceder a otros campos según necesites
                    continue
                except:
                    pass
                
                # Intenta parsear como AmfMessage (AMF enviando)
                try:
                    amf_msg = AmfMessage()
                    amf_msg.ParseFromString(payload)
                    print("\n=== Mensaje AMF -> SCTPLB ===")
                    print(f"Tipo: {amf_msg.Msgtype}")
                    print(f"AMF ID: {amf_msg.AmfId}")
                    print(f"gNB Destino: {amf_msg.GnbId}")
                    print(f"Redirección a: {amf_msg.RedirectId or 'N/A'}")
                    continue
                except:
                    pass
                
                print("\n=== Paquete no parseable ===")
                print(f"Payload hex: {payload.hex()}")
                