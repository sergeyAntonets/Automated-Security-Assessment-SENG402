from Network import *
from Vulnerability import *

# Global lists to store vulnerability data
enterprise_vulnerabilities_original = []
enterprise_vulnerabilities_predicted = []


def create_two_device_enterprise_network(device_vulnerabilities_list):
    """
    Create a simple enterprise network with two devices: Windows PC and Linux Server
    
    Args:
        device_vulnerabilities_list: List containing vulnerability data for each device
                                   [0] = Windows PC vulnerabilities
                                   [1] = Linux Server vulnerabilities
    
    Returns:
        network: The constructed enterprise network with HARM representation
    """
    
    # Create Windows PC workstation device
    windows_workstation = iot('Windows_Workstation')
    windows_workstation.subnet.append('corporate_lan')
    
    # Assign vulnerabilities to Windows PC
    if len(device_vulnerabilities_list) > 0 and len(device_vulnerabilities_list[0]) > 0:
        windows_pc_primary_vulnerability = device_vulnerabilities_list[0][0]
        windows_pc_primary_vulnerability.createVuls(windows_workstation)
        windows_pc_primary_vulnerability.thresholdPri(windows_workstation, 1)
        windows_pc_primary_vulnerability.terminalPri(windows_workstation, 1)
    
    # Create Linux Server device
    linux_application_server = iot('Linux_Application_Server')
    linux_application_server.subnet.append('corporate_lan')
    
    # Assign vulnerabilities to Linux Server
    if len(device_vulnerabilities_list) > 1 and len(device_vulnerabilities_list[1]) > 0:
        linux_server_primary_vulnerability = device_vulnerabilities_list[1][0]
        linux_server_primary_vulnerability.createVuls(linux_application_server)
        linux_server_primary_vulnerability.thresholdPri(linux_application_server, 1)
        linux_server_primary_vulnerability.terminalPri(linux_application_server, 1)
    
    # Create the enterprise network topology
    enterprise_network = network()
    enterprise_network.setName('Two_Device_Enterprise_Network')
    
    # Establish network connections (bidirectional communication)
    enterprise_network.connectTwoWays(windows_workstation, linux_application_server)
    
    # Add devices to the network
    enterprise_network.nodes.append(windows_workstation)
    enterprise_network.nodes.append(linux_application_server)
    
    # Create external attacker node
    external_threat_actor = computer('External_Attacker')
    external_threat_actor.setStart()
    
    # Define attack entry point - attacker initially compromises Windows workstation
    external_threat_actor.connections.append(windows_workstation)
    
    # Set attack target - Linux server contains critical business data
    linux_application_server.setEnd()
    
    # Add attacker to network and construct security evaluator
    enterprise_network.nodes.append(external_threat_actor)
    enterprise_network.constructSE()
    enterprise_network.printNet()
    
    return enterprise_network
