#!/usr/bin/env python3
"""
Network Traffic Analyzer
Analyzes traffic from Wireshark files (.pcap) and creates visual routes and statistics

Requirements:
pip install scapy matplotlib networkx pandas seaborn requests folium

Usage:
python traffic_analyzer.py capture.pcap
"""

import argparse
import os
import sys
import json
from collections import Counter, defaultdict
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import networkx as nx
import requests
import webbrowser
from datetime import datetime
import socket

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS
except ImportError:
    print("Error: install scapy -> pip install scapy")
    sys.exit(1)

class NetworkTrafficAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.packets = []
        self.connections = defaultdict(int)
        self.protocols = Counter()
        self.ip_stats = Counter()
        self.port_stats = Counter()
        self.dns_queries = []
        self.geo_data = {}
        
    def load_pcap(self):
        """Loads and parses pcap file"""
        print(f"📊 Loading pcap file: {self.pcap_file}")
        try:
            self.packets = rdpcap(self.pcap_file)
            print(f"✅ Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"❌ File loading error: {e}")
            return False
    
    def analyze_traffic(self):
        """Analyzes traffic and collects statistics"""
        print("🔍 Analyzing traffic...")
        
        for i, packet in enumerate(self.packets):
            if i % 1000 == 0:
                print(f"Processed {i}/{len(self.packets)} packets")
            
            # IP analysis
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # IP statistics
                self.ip_stats[src_ip] += 1
                self.ip_stats[dst_ip] += 1
                
                # Connections
                connection = f"{src_ip} -> {dst_ip}"
                self.connections[connection] += 1
                
                # Protocols
                if TCP in packet:
                    self.protocols['TCP'] += 1
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    self.port_stats[dst_port] += 1
                elif UDP in packet:
                    self.protocols['UDP'] += 1
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    self.port_stats[dst_port] += 1
                else:
                    self.protocols['Other'] += 1
                
                # DNS queries
                if DNS in packet and packet[DNS].qr == 0:  # DNS query
                    dns_query = packet[DNS].qd.qname.decode('utf-8').rstrip('.')
                    self.dns_queries.append(dns_query)
        
        print(f"✅ Analysis completed. Found {len(self.connections)} unique connections")
    
    def get_geolocation(self, ip):
        """Gets geolocation for IP address (free service)"""
        if ip in self.geo_data:
            return self.geo_data[ip]
        
        # Skip local IPs
        if ip.startswith(('192.168.', '10.', '172.16.')) or ip == '127.0.0.1':
            self.geo_data[ip] = {"country": "Local", "city": "Local", "lat": 0, "lon": 0}
            return self.geo_data[ip]
        
        try:
            # Using free API ip-api.com
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data['status'] == 'success':
                    self.geo_data[ip] = {
                        "country": data.get('country', 'Unknown'),
                        "city": data.get('city', 'Unknown'),
                        "lat": data.get('lat', 0),
                        "lon": data.get('lon', 0)
                    }
                else:
                    self.geo_data[ip] = {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
            else:
                self.geo_data[ip] = {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
        except:
            self.geo_data[ip] = {"country": "Unknown", "city": "Unknown", "lat": 0, "lon": 0}
        
        return self.geo_data[ip]
    
    def create_network_graph(self):
        """Creates network connections graph"""
        print("🌐 Creating network connections graph...")
        
        G = nx.DiGraph()
        
        # Add top-20 connections for readability
        top_connections = dict(Counter(self.connections).most_common(20))
        
        for connection, weight in top_connections.items():
            src, dst = connection.split(' -> ')
            G.add_edge(src, dst, weight=weight)
        
        # Create visualization
        plt.figure(figsize=(15, 10))
        pos = nx.spring_layout(G, k=2, iterations=50)
        
        # Draw nodes
        node_sizes = [self.ip_stats[node] * 10 for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_size=node_sizes, 
                              node_color='lightblue', alpha=0.7)
        
        # Draw edges with weights
        edges = G.edges()
        weights = [G[u][v]['weight'] for u, v in edges]
        nx.draw_networkx_edges(G, pos, width=[w/max(weights)*5 for w in weights],
                              alpha=0.6, edge_color='gray', arrows=True)
        
        # Node labels
        labels = {node: node.split('.')[-1] for node in G.nodes()}  # Show only last octet
        nx.draw_networkx_labels(G, pos, labels, font_size=8)
        
        plt.title("Network Connections Graph (Top-20)", fontsize=16)
        plt.axis('off')
        plt.tight_layout()
        plt.savefig('network_graph.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("💾 Graph saved to file: network_graph.png")
    
    def create_statistics_charts(self):
        """Creates various statistics charts"""
        print("📊 Creating statistics charts...")
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # 1. Top protocols
        protocols = dict(self.protocols.most_common(10))
        ax1.pie(protocols.values(), labels=protocols.keys(), autopct='%1.1f%%')
        ax1.set_title('Protocol Distribution')
        
        # 2. Top IP addresses
        top_ips = dict(self.ip_stats.most_common(10))
        ax2.barh(list(top_ips.keys()), list(top_ips.values()))
        ax2.set_title('Top IP Addresses by Packet Count')
        ax2.set_xlabel('Packet Count')
        
        # 3. Top ports
        top_ports = dict(self.port_stats.most_common(10))
        ax3.bar(range(len(top_ports)), list(top_ports.values()))
        ax3.set_xticks(range(len(top_ports)))
        ax3.set_xticklabels(list(top_ports.keys()), rotation=45)
        ax3.set_title('Top Destination Ports')
        ax3.set_ylabel('Connection Count')
        
        # 4. Top connections
        top_conn = dict(Counter(self.connections).most_common(10))
        conn_labels = [conn.replace(' -> ', '\\n→\\n') for conn in top_conn.keys()]
        ax4.barh(range(len(top_conn)), list(top_conn.values()))
        ax4.set_yticks(range(len(top_conn)))
        ax4.set_yticklabels(conn_labels, fontsize=8)
        ax4.set_title('Top Connections')
        ax4.set_xlabel('Packet Count')
        
        plt.tight_layout()
        plt.savefig('traffic_statistics.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("💾 Statistics saved to file: traffic_statistics.png")
    
    def create_geo_map(self):
        """Creates map with geographical traffic points"""
        print("🗺️  Creating geographical map...")
        
        # Collect unique IPs for geolocation
        unique_ips = set()
        for connection in list(self.connections.keys())[:20]:  # Top-20 to save API requests
            src, dst = connection.split(' -> ')
            unique_ips.add(src)
            unique_ips.add(dst)
        
        # Get geolocation
        geo_points = []
        for ip in unique_ips:
            geo = self.get_geolocation(ip)
            if geo['lat'] != 0 or geo['lon'] != 0:
                geo_points.append({
                    'ip': ip,
                    'country': geo['country'],
                    'city': geo['city'],
                    'lat': geo['lat'],
                    'lon': geo['lon'],
                    'packets': self.ip_stats[ip]
                })
        
        if not geo_points:
            print("⚠️  No public IPs found for geolocation")
            return
        
        # Create simple scatter plot
        plt.figure(figsize=(15, 8))
        
        countries = [point['country'] for point in geo_points]
        country_counts = Counter(countries)
        
        plt.subplot(1, 2, 1)
        plt.pie(country_counts.values(), labels=country_counts.keys(), autopct='%1.1f%%')
        plt.title('Geographical Traffic Distribution')
        
        plt.subplot(1, 2, 2)
        lats = [point['lat'] for point in geo_points]
        lons = [point['lon'] for point in geo_points]
        sizes = [point['packets'] for point in geo_points]
        
        plt.scatter(lons, lats, s=[s/10 for s in sizes], alpha=0.6)
        plt.xlabel('Longitude')
        plt.ylabel('Latitude')
        plt.title('Geographical Traffic Points')
        
        for point in geo_points:
            plt.annotate(point['country'], (point['lon'], point['lat']), 
                        fontsize=8, alpha=0.7)
        
        plt.tight_layout()
        plt.savefig('geo_traffic.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("💾 Geographical map saved to file: geo_traffic.png")
    
    def generate_report(self):
        """Generates text report"""
        print("📝 Generating report...")
        
        report = f"""
=== NETWORK TRAFFIC ANALYSIS REPORT ===
File: {self.pcap_file}
Analysis time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

📊 GENERAL STATISTICS:
- Total packets: {len(self.packets)}
- Unique IP addresses: {len(self.ip_stats)}
- Unique connections: {len(self.connections)}

🌐 TOP-10 IP ADDRESSES:
"""
        for ip, count in self.ip_stats.most_common(10):
            report += f"  {ip:<15} - {count:>6} packets\n"

        report += f"""
🔗 TOP-10 CONNECTIONS:
"""
        for conn, count in Counter(self.connections).most_common(10):
            report += f"  {conn:<35} - {count:>4} packets\n"

        report += f"""
📡 PROTOCOLS:
"""
        for proto, count in Counter(self.protocols).most_common():
            report += f"  {proto:<10} - {count:>6} packets ({count/len(self.packets)*100:.1f}%)\n"

        report += f"""
🚪 TOP-10 PORTS:
"""
        for port, count in Counter(self.port_stats).most_common(10):
            report += f"  Port {port:<6} - {count:>4} connections\n"

        if self.dns_queries:
            report += f"""
🔍 TOP-10 DNS QUERIES:
"""
            dns_counter = Counter(self.dns_queries)
            for domain, count in dns_counter.most_common(10):
                report += f"  {domain:<30} - {count:>3} queries\n"

        # Save report
        with open('traffic_report.txt', 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.generate_html_report(report)
        
        print(report)
        print("💾 Report saved to file: traffic_report.txt")
        print("📄 HTML report saved to file: traffic_report.html")

    def generate_html_report(self, report_text):
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Network Traffic Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }}
        pre {{ background: #f8f8f8; padding: 20px; border-radius: 5px; overflow-x: auto; }}
        .timestamp {{ color: #666; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Traffic Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <pre>{report_text}</pre>
    </div>
</body>
</html>
"""
        with open('traffic_report.html', 'w', encoding='utf-8') as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description='Network traffic analysis from Wireshark')
    parser.add_argument('pcap_file', help='Path to .pcap file')
    parser.add_argument('--no-geo', action='store_true', help='Skip geolocation')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.pcap_file):
        print(f"❌ File not found: {args.pcap_file}")
        sys.exit(1)
    
    print("🚀 Starting network traffic analyzer")
    print("=" * 50)
    
    analyzer = NetworkTrafficAnalyzer(args.pcap_file)
    
    # Load and analyze
    if not analyzer.load_pcap():
        sys.exit(1)
    
    analyzer.analyze_traffic()
    
    # Create visualizations
    analyzer.create_network_graph()
    analyzer.create_statistics_charts()
    
    if not args.no_geo:
        analyzer.create_geo_map()
    
    # Generate report
    analyzer.generate_report()
    
    print("\n✅ Analysis completed! Created files:")
    print("  - network_graph.png (connections graph)")
    print("  - traffic_statistics.png (statistics)")
    if not args.no_geo:
        print("  - geo_traffic.png (geographical map)")
    print("  - traffic_report.txt (text report)")

if __name__ == '__main__':
    main()
