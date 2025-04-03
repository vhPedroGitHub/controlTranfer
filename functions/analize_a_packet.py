from scapy.all import TCP, Raw
from textwrap import wrap

def get_payload(packet):
    """
    Analiza un paquete TCP y devuelve un string con su contenido y payload.
    
    Args:
        packet: Paquete de red capturado con Scapy
    
    Returns:
        str: String formateado con la información del paquete TCP y su payload
    """
    output = []
    # Payload
    if packet.haslayer(Raw):
        raw = packet[Raw].load
        payload_size = len(raw)
        output.append(f"\n🔹 Payload ({payload_size} bytes):")
        
        # Hexadecimal y ASCII
        hex_bytes = raw.hex()
        hex_groups = wrap(hex_bytes, 2)  # Separa en bytes (2 caracteres hex)
        hex_lines = wrap(' '.join(hex_groups), 48)  # 16 bytes por línea (16*3-1=47 caracteres)
        
        ascii_repr = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw])
        ascii_lines = wrap(ascii_repr, 16)
        
        # Formato al estilo hexdump
        output.append("\n    OFFSET   HEX                                              ASCII")
        output.append("    " + "-"*60)
        
        for i, (hex_line, ascii_line) in enumerate(zip(hex_lines, ascii_lines)):
            offset = i * 16
            hex_part = hex_line.ljust(47)
            output.append(f"    {offset:04X}h: {hex_part}  {ascii_line}")
    else:
        output.append("\n🔹 No se detectó payload en el paquete TCP")

    return '\n'.join(output)