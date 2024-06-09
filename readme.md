# NetScan Visualizer: Mapping and Securing Networks

NetScan Visualizer is a Python script designed to scan a network range, identify potential threats based on known vulnerable ports, and visualize the network topology along with the discovered services.

## Features

- **Network Scanning:** Utilizes the `nmap` library to scan a specified network range for active hosts and open ports.
- **Threat Identification:** Identifies potential threats by comparing open ports with a predefined list of known vulnerable ports.
- **Network Visualization:** Generates a visual representation of the network topology using `networkx` and `matplotlib`.
- **Detailed Port Information:** Provides detailed information about open ports on each host, including state, service name, product, and version.

## Requirements

- Python 3.x
- `nmap` Python library (`python-nmap`)
- `networkx` library
- `matplotlib` library
- `pandas` library

## Install Dependencies Using:

pip install python-nmap networkx matplotlib pandas

## Input Network Range

When prompted, enter the network range you want to scan (e.g., 192.168.1.0/24).

## Sequenced Output 

![image](https://github.com/nradhesh/NetScan-Visualizer--Mapping-and-Securing-Networks/assets/136627964/5c30bff9-90cf-4c29-b574-38b010d9aea2)

The script will display potential threats detected based on known vulnerable ports.

It will generate a visual representation of the network topology.

Detailed port information for each host will be provided. 

Based on the open ports and the services on these ports the reason of causing DoS attack can be detected.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
