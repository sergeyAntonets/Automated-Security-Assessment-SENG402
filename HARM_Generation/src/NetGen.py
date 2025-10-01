"""
Module responsible for creating a network and the devices.
"""

from Network import Network
from Node import Device
from Vulnerability import VulnerabilityNode
from VulnerabilityNetwork import VulnerabilityNetwork
from Harm import Harm
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scripts.get_vulnerabilities_for_CPE import *

def addVulnerabilitiesToDevice(device: Device):
    """
    Helper function to fetch vulnerabilities for the device's CPE and add them to the device's vulnerability network.
    :param device: Device object to which vulnerabilities will be added
    """

    # Fetch vulnerabilities for the device's CPE from saved file or NVD
    vulnerabilities_data = fetch_CVEs_for_CPE(device.CPE, number_of_CVEs=15)

    # Create a list of VulnerabilityNode objects
    vulnerability_nodes = []
    for vuln_data in vulnerabilities_data:
        node = VulnerabilityNode("")  # Create node
        node.construct_vulnerability(vuln_data, device.CPE)  # Populate node
        vulnerability_nodes.append(node)

    # Create the VulnerabilityNetwork by passing the list of nodes to the constructor
    device.vulnerabilities = VulnerabilityNetwork(vulnerability_nodes)

def createSimpleNetwork():
    """
    Create a simple network with two devices.
    :returns: network: the created network
    """

    # CPE for PC device
    device1_CPE="cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*"
    # CPE for server device
    device2_CPE="cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*"
    
    # Create clinet computer, set it as the starting point for attacker and add vulnerabilities to it
    device1 = Device("WindowsPC", device1_CPE)
    device1.setStart()
    addVulnerabilitiesToDevice(device1)

    # Add server computer, set it as the end point of the attack and add vulnerabilities to it
    device2 = Device("LinuxServer", device2_CPE)
    device2.setEnd()
    addVulnerabilitiesToDevice(device2)

    # Create a new network
    network = Network()
    network.name = "Simple 2-device network"

    # Add the devices to the network
    network.nodes.append(device1)
    network.nodes.append(device2)

    # Set the start and end points in the network
    network.constructSE()
    

    # Connect devices on the network
    network.connectTwoWays(device1, device2)

    # Return the created network
    return network

def createEnterpriseNetwork():
    """
    Create a more complex network with multiple devices.
    :returns: network: the created network
    """

    # Create devices
    
    # Initialize the windows workstation, set it as the starting point for attacker and add vulnerabilities to it
    win_workstation = Device("WindowsWorkstation", "cpe:2.3:o:microsoft:windows_10_21h2:-:*:*:*:*:*:arm64:*")
    win_workstation.setStart()
    addVulnerabilitiesToDevice(win_workstation)
    win_workstation.subnet.append("Workstations")
    
    # Initialize the mac workstation and add vulnerabilities to it
    mac_workstation = Device("MacWorkstation", "cpe:2.3:o:apple:macos:11.3.1:*:*:*:*:*:*:*")
    addVulnerabilitiesToDevice(mac_workstation)
    mac_workstation.subnet.append("Workstations")

    # Initialize the web server, set it as the end point of the attack and add vulnerabilities to it
    web_server = Device("WebServer", "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*")
    web_server.subnet.append("DMZ")
    addVulnerabilitiesToDevice(web_server)

    # Initialize the DNS server and add vulnerabilities to it
    dns_server = Device("DNSServer", "cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*")
    addVulnerabilitiesToDevice(dns_server)
    dns_server.subnet.append("DMZ")

    # Initialize the database server, set it as the end point of the attack and add vulnerabilities to it
    db_server = Device("DatabaseServer", "cpe:2.3:a:postgresql:postgresql:14.1:*:*:*:*:*:*:*")
    db_server.setEnd()
    addVulnerabilitiesToDevice(db_server)
    db_server.subnet.append("Internal")

    # Create the enterprise network
    enterprise_network = Network()
    enterprise_network.name = "Enterprise Network"

    # WITHIN SUBNET CONNECTIONS
    # DMZ devices can communicate
    enterprise_network.connectTwoWays(web_server, dns_server)

    # Workstations can communicate
    enterprise_network.connectTwoWays(mac_workstation, win_workstation)

    # CROSS-SUBNET CONNECTIONS (Direct)
    # Web server needs database access
    enterprise_network.connectTwoWays(web_server, db_server)  # DMZ ↔ Internal

    # Workstations need database access
    enterprise_network.connectTwoWays(mac_workstation, db_server) # Workstation ↔ Internal
    enterprise_network.connectTwoWays(win_workstation, db_server) # Workstation ↔ Internal

    # Add all nodes to network
    enterprise_network.nodes.extend([web_server, dns_server, mac_workstation, win_workstation, db_server])
    
    # Set the start and end points in the network
    enterprise_network.constructSE()
    
    return enterprise_network



def main():
    """
    The entry point for network generation.
    """

    # simple_network = createSimpleNetwork()
    enterprise_network = createEnterpriseNetwork()
    print(enterprise_network)

    harm = Harm()
    harm.constructHarm(enterprise_network, "attackgraph",1,"attacktree",1,3)
    harm.model.printAG()
    print("!!!HERE!!")
    harm.model.printPath()




# Entry point for script execution
main()