from scapy.all import IP, TCP, UDP, ICMP, IPv6

def get_packet_errors(packet):
    """Analiza un paquete y devuelve una cadena con todos los errores detectados."""
    errors = []
    
    try:
        # Reconstruimos el paquete con checksums recalculados
        rebuilt_packet = packet.__class__(bytes(packet))
        rebuilt_bytes = packet.build(auto_cksum=True)
        rebuilt_packet = packet.__class__(rebuilt_bytes)
    except Exception as e:
        return f"Error al procesar el paquete: {str(e)}"
    
    # Verificación de checksums
    def _check_layer(proto, name):
        if packet.haslayer(proto):
            original = packet[proto]
            rebuilt = rebuilt_packet[proto]
            if original.chksum != rebuilt.chksum:
                errors.append(f"{name} checksum inválido (original: {original.chksum}, correcto: {rebuilt.chksum})")
    
    _check_layer(IP, "IP")
    _check_layer(TCP, "TCP")
    _check_layer(ICMP, "ICMP")
    
    # Verificación especial para UDP (checksum opcional en IPv4)
    if packet.haslayer(UDP):
        udp = packet[UDP]
        rebuilt_udp = rebuilt_packet[UDP]
        if udp.chksum != rebuilt_udp.chksum:
            if packet.haslayer(IP) and packet[IP].version == 4 and udp.chksum == 0:
                pass  # Checksum opcional en IPv4
            elif packet.haslayer(IPv6) and udp.chksum == 0:
                errors.append("UDP checksum cero (inválido en IPv6)")
            else:
                errors.append(f"UDP checksum inválido (original: {udp.chksum}, correcto: {rebuilt_udp.chksum})")
    
    # Verificación de banderas TCP
    if packet.haslayer(TCP):
        flags = packet[TCP].flags
        if 'S' in flags and 'F' in flags:
            errors.append("Combinación inválida de banderas TCP: SYN y FIN simultáneos")
        if 'S' in flags and 'R' in flags:
            errors.append("Combinación inválida de banderas TCP: SYN y RST simultáneos")
    
    # Verificación de longitudes
    if packet.haslayer(IP):
        ip = packet[IP]
        if ip.len != len(ip):
            errors.append(f"Longitud IP incorrecta (campo: {ip.len}, real: {len(ip)})")
    
    if packet.haslayer(UDP):
        udp = packet[UDP]
        if udp.len != len(udp):
            errors.append(f"Longitud UDP incorrecta (campo: {udp.len}, real: {len(udp)})")
    
    # Verificación de offset TCP
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        header_len = len(tcp) - len(tcp.payload)
        if tcp.dataofs * 4 != header_len:
            errors.append(f"Data Offset TCP incorrecto (declarado: {tcp.dataofs*4} bytes, real: {header_len} bytes)")
    
    return "\n".join(errors) if errors else "No se detectaron errores"