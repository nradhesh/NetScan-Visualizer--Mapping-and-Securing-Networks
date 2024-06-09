import nmap
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd

def scan_network(network_range):
    nm = nmap.PortScanner()
    print(f"Scanning network: {network_range}...")
    nm.scan(hosts=network_range, arguments='-sV')
    
    network_map = {}
    for host in nm.all_hosts():
        print(f"Host found: {host}")
        host_info = {
            'hostname': nm[host].hostname(),
            'state': nm[host].state(),
            'protocols': {}
        }
        for protocol in nm[host].all_protocols():
            port_info = nm[host][protocol]
            host_info['protocols'][protocol] = port_info
            for port in port_info:
                print(f"  Protocol: {protocol}, Port: {port}, State: {port_info[port]['state']}")
            
        network_map[host] = host_info
    print("Scan complete.")
    return network_map

def identify_threats(network_map):
    threats = []
    known_vulnerable_ports = [21, 22, 53, 25, 80, 110, 143, 443, 3389]  # Example vulnerable ports
    
    for host, info in network_map.items():
        for protocol, ports in info['protocols'].items():
            for port, port_info in ports.items():
                if port in known_vulnerable_ports:
                    threats.append((host, port, port_info['state'], protocol))
                    print(f"Potential threat detected: {host} - {protocol}:{port} ({port_info['state']})")
    
    return threats

def visualize_network(network_map):
    G = nx.Graph()
    
    for host, info in network_map.items():
        hostname = info['hostname'] if info['hostname'] else host
        G.add_node(host, label=hostname)
        
        for protocol, ports in info['protocols'].items():
            for port, state in ports.items():
                service_info = f"{protocol}:{port} ({state['state']})"
                G.add_edge(host, service_info)
    
    pos = nx.spring_layout(G)
    labels = nx.get_edge_attributes(G, 'label')
    node_labels = nx.get_node_attributes(G, 'label')
    
    nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=2000, node_color='skyblue', font_size=10, font_weight='bold')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_color='red')
    plt.title('Network Map')
    plt.show()

def display_port_table(network_map):
    for host, info in network_map.items():
        print(f"Host: {host} - Hostname: {info['hostname']} - State: {info['state']}")
        if info['protocols']:
            for protocol, ports in info['protocols'].items():
                port_df = pd.DataFrame.from_dict(ports, orient='index')
                print(f"\nProtocol: {protocol}")
                print(port_df[['state', 'name', 'product', 'version']])
                print("-" * 50)
        else:
            print("No open ports detected for this host.")
        print("=" * 20, "SCAN ENDED", "="*20)

if __name__ == "__main__":
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")

    network_map = scan_network(network_range)
    
    if not network_map:
        print("No hosts found. Ensure the network range is correct and try again.")
    else:
        threats = identify_threats(network_map)
        if not threats:
            print("No potential threats detected.")
        else:
            print(f"Detected {len(threats)} potential threats.")
            print('-'*70)
            print("")
            
            print(f"Threats: {threats}")
            print('-'*70)
            print("")
        visualize_network(network_map)
        print('-'*70)
        print("")
        display_port_table(network_map)
