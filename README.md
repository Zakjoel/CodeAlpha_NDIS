# 🌟 CodeAlpha_NDIS
## Network Intrusion Detection System


### Code Explanation:
The above program is for a rudimentary Real-Time Intrusion Detection system using  Python. The core library we use for packet sniffing is Scapy, which is a powerful Python-based interactive packet manipulation program & library.

### 🚀 Here’s a step-by-step breakdown:


We first import necessary modules: socket for network interactions, sys for system-specific parameters and functions, time for time-related tasks, and scapy for packet sniffing and crafting.
A Counter from the collections module is used to keep track of the number of packets originating from each source IP address.
The RealTimeIntrusionDetector class is where the main functionality resides. This class accepts a threshold parameter, which is the packet count from a single IP that we consider as the point at which traffic is potentially malicious or anomalous.
A dummy function, detect_anomaly, is designed to simply check if the packet source IP has sent more packets than the threshold. A real-world scenario would require a more advanced form of anomaly detection, perhaps incorporating machine learning models that have been trained on normal vs. anomalous traffic patterns.
The packet_handler function is called by Scapy for every packet sniffed. It increments the ip_counter for the source IP of each packet. If the threshold is surpassed, it prints out an intrusion detection alert.
The sniff_traffic function starts the packet sniffing process with Scapy’s sniff function, passing the packet handler as the callback for each sniffed packet, and setting store as False to prevent keeping all packets in memory.
In the if __name__ == '__main__': section, we instantiate the RealTimeIntrusionDetector and start the traffic sniffing.
The expected console output will show a starting message, followed by intrusion detection alerts if any source IP exceeds the defined threshold of packets.

## 🔧 Requirements
Python 3.x
Scapy
sys
Socket
user_agents
time
collections
## 📖 Usage
Run the script (python3 NIDS.py).
Terminate by pressing Ctrl+C.
