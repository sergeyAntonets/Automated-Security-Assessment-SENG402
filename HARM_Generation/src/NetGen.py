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

    # Set start and end devices in the network
    network.start = device1
    network.end = device2

    # Connect devices on the network
    network.connectTwoWays(device1, device2)

    # Return the created network
    return network


def main():
    """
    The entry point for network generation.
    """

    simple_network = createSimpleNetwork()
    print(simple_network)

    harm = Harm()
    harm.constructHarm(simple_network, "attackgraph",1,"attacktree",1,3)



# Entry point for script execution
main()