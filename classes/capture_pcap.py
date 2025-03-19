from scapy.all import rdpcap, IP, TCP
import os

class CapturePcap:
    def __init__(self, capture, pod_name):
        self.capture = rdpcap(f"{capture}")
        self.pod_name = pod_name

    @staticmethod
    def from_directory(directory):
        file_paths = CapturePcap.get_file_paths(directory)
        captures = []
        for path in file_paths:
            pod_name = os.path.basename(path).split('/')[-1].replace('.pcap', '')
            captures.append(CapturePcap(path, pod_name))
        return captures

    @staticmethod
    def get_file_paths(directory):
        print(directory)
        file_paths = []
        for root, _, files in os.walk(directory):
            for file in files:
                print(file)
                if file.endswith('.pcap'):
                    print(file)
                    file_paths.append(f"{directory}/{file}")
        return file_paths