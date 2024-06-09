# Import necessary libraries
import nmap
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd

# Function to scan the network using nmap
def scan_network(network_range):
    nm = nmap.PortScanner()  # Initialize nmap PortScanner object
    print(f"Scanning network: {network_range}...")  # Print scanning message
    nm.scan(hosts=network_range, arguments='-sV')  # Scan the network with specified arguments
    
    network_map = {}  # Initialize an empty dictionary to store scan results
    for host in nm.all_hosts():  # Iterate through all scanned hosts
        print(f"Host found: {host}")  # Print the found host
        host_info = {  # Initialize a dictionary to store information about the host
            'hostname': nm[host].hostname(),  # Hostname of the scanned host
            'state': nm[host].state(),  # State of the host (up or down)
            'protocols': {}  # Initialize an empty dictionary to store protocols and ports
        }
        for protocol in nm[host].all_protocols():  # Iterate through protocols (TCP, UDP)
            port_info = nm[host][protocol]  # Information about ports for the protocol
            host_info['protocols'][protocol] = port_info  # Store port information under protocol
            for port in port_info:  # Iterate through ports
                print(f"  Protocol: {protocol}, Port: {port}, State: {port_info[port]['state']}")  # Print port information
        network_map[host] = host_info  # Store host information in the network map dictionary
    print("Scan complete.")  # Print message indicating scan completion
    return network_map  # Return the network map dictionary containing scan results

# Function to identify potential threats based on known vulnerable ports
def identify_threats(network_map):
    threats = []  # Initialize an empty list to store potential threats
    known_vulnerable_ports = [21, 22, 53, 25, 80, 110, 143, 443, 3389]  # List of known vulnerable ports
    
    for host, info in network_map.items():  # Iterate through hosts in the network map
        for protocol, ports in info['protocols'].items():  # Iterate through protocols and ports
            for port, port_info in ports.items():  # Iterate through port information
                if port in known_vulnerable_ports:  # Check if the port is known to be vulnerable
                    threats.append((host, port, port_info['state'], protocol))  # Add potential threat to the list
                    print(f"Potential threat detected: {host} - {protocol}:{port} ({port_info['state']})")  # Print threat information
    
    return threats  # Return the list of potential threats

# Function to visualize the network using NetworkX and Matplotlib
def visualize_network(network_map):
    G = nx.Graph()  # Initialize a graph object
    
    for host, info in network_map.items():  # Iterate through hosts in the network map
        hostname = info['hostname'] if info['hostname'] else host  # Get hostname or IP address
        G.add_node(host, label=hostname)  # Add node for the host
        
        for protocol, ports in info['protocols'].items():  # Iterate through protocols and ports
            for port, state in ports.items():  # Iterate through ports and their states
                service_info = f"{protocol}:{port} ({state['state']})"  # Format service information
                G.add_edge(host, service_info)  # Add edge between host and service
                
    pos = nx.spring_layout(G)  # Compute node positions using spring layout
    labels = nx.get_edge_attributes(G, 'label')  # Get edge labels
    node_labels = nx.get_node_attributes(G, 'label')  # Get node labels
    
    nx.draw(G, pos, with_labels=True, labels=node_labels, node_size=2000, node_color='skyblue', font_size=10, font_weight='bold')  # Draw the graph
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, font_color='red')  # Draw edge labels
    plt.title('Network Map')  # Set plot title
    plt.show()  # Show the plot

# Function to display port information in a tabular format
def display_port_table(network_map):
    for host, info in network_map.items():  # Iterate through hosts in the network map
        print(f"Host: {host} - Hostname: {info['hostname']} - State: {info['state']}")  # Print host information
        if info['protocols']:  # Check if protocols are found for the host
            for protocol, ports in info['protocols'].items():  # Iterate through protocols and ports
                port_df = pd.DataFrame.from_dict(ports, orient='index')  # Create DataFrame from port information
                print(f"\nProtocol: {protocol}")  # Print protocol
                print(port_df[['state', 'name', 'product', 'version']])  # Print port details
                print("-" * 50)  # Print separator line
        else:
            print("No open ports detected for this host.")  # Print message if no open ports found
        print("=" * 20, "SCAN ENDED", "="*20)  # Print scan end indicator

# Main function
if __name__ == "__main__":
    network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")  # Get network range from user
    
    network_map = scan_network(network_range)  # Scan the network
    
    if not network_map:  # Check if no hosts are found
        print("No hosts found. Ensure the network range is correct and try again.")
    else:
        threats = identify_threats(network_map)  # Identify potential threats
        if not threats:  # Check if no threats are found
            print("No potential threats detected.")
        else:
            print(f"Detected {len(threats)} potential threats.")  # Print the number of detected threats
            print('-'*70)  # Print separator line
            
            print(f"Threats: {threats}")  # Print detected threats
            print('-'*70)  # Print separator line
            
        visualize_network(network_map)  # Visualize the network
        print('-'*70)  # Print separator line
        
        display_port_table(network_map)  # Display port information in a table
