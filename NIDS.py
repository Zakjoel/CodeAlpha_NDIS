import socket
import sys
import time
from scapy.all import *
from collections import Counter

class RealTimeIntrusionDetector:
    def __init__(self, threshold=10):
        self.threshold = threshold
        self.ip_counter = Counter()

    # Dummy anomaly detection function, replace with actual logic
    def detect_anomaly(self, packet):
        return packet[IP].src in self.ip_counter and self.ip_counter[packet[IP].src] > self.threshold

    def packet_handler(self, packet):
        if IP in packet:
            self.ip_counter[packet[IP].src] += 1
            if self.detect_anomaly(packet):
                print(f'Intrusion detected from {packet[IP].src}!')

    def sniff_traffic(self):
        sniff(prn=self.packet_handler, store=False)

if __name__ == '__main__':
    detector = RealTimeIntrusionDetector()

    print('Starting network traffic monitoring!')
    detector.sniff_traffic()
