from scapy.all import rdpcap, PcapReader, PacketList
import os
def read_first_n_packets(file_path, n):
    packets = []
    with PcapReader(file_path) as pcap_reader:
        for i, packet in enumerate(pcap_reader):
            if i >= n:  # Limitar a los primeros N paquetes
                break
            packets.append(packet)
    return PacketList(packets)

class CapturePcap:
    def __init__(self, capture, pod_name, limit):
        try:
            if limit > 0:
                self.capture = read_first_n_packets(capture, limit)
                print(self.capture, limit)
            else:
                self.capture = PcapReader(capture)
                print(self.capture)

            self.valid = True
        except Exception as e:
            print(f"Error cargando {capture}: {str(e)}")
            self.capture = None
            self.valid = False
        self.pod_name = pod_name

    @staticmethod
    def from_directory(directory, limit):
        file_paths = CapturePcap.get_file_paths(directory)
        captures = []
        for path in file_paths:
            pod_name = os.path.splitext(os.path.basename(path))[0]
            captures.append(CapturePcap(path, pod_name, limit))
        return [c for c in captures if c.valid]

    @staticmethod
    def get_file_paths(directory):
        print(directory)
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                print(file)
                if file.endswith('.pcap') or '.' not in file:
                    print(file)
                    file_paths.append(os.path.join(root, file))
        return file_paths