

from Node import *
from Network import *
from Vulnerability import *


class tNode(node):
    """
    Create attack tree node object.
    """
    def __init__(self, name):
        super(tNode, self).__init__(name)
        self.node = None
        self.t = "node"
        self.val = 0
        # self.mv3 = metrics_v3()
    
    def __str__(self):
        return self.name

class tVulNode(VulnerabilityNode):
    """
    Create attack tree vulnerability object.
    """
    def __init__(self, name):
        super(tVulNode, self).__init__(name)
        self.node = None
        self.t = "node"
        self.val = 0
        self.command = 0
        # self.mv3 = metrics_v3()
        
    def __str__(self):
        return self.name
      
class andGate(node):
    def __init__(self):
        super(andGate, self).__init__("andGate")
        self.t = "andGate"

class orGate(node):
    def __init__(self):
        super(orGate, self).__init__("orGate")
        self.t = "orGate"

     
class AttackTree(object):
    """
    Create attack tree.
    """
    def __init__(self, network, val, *arg):
        self.nodes = []
        self.topGate = None
        self.construct(network, val, *arg)
        self.isAG = 0
    
    #Preprocess for the construction
    def preprocess(self, network, nodes, val, *arg):  
        for network_node in [network.start, network.end] + network.nodes:
            if network_node is not None:
                #For vulNode
                if type(network_node) is VulnerabilityNode:
                    tree_node = tVulNode('at_'+str(network_node.name))
                    tree_node.postcondition = network_node.postcondition
                    # tn.mv2 = u.mv2
                    tree_node.vulname = network_node.name
                #For node
                else:
                    tree_node = tNode('at_'+str(network_node.name))
                    
                    #Assign default value to attacker node
                    if network_node.isStart == True:
                        tree_node.val = -1
                    else:
                        tree_node.val = val
                    
                tree_node.node = network_node
                
                #Assign default value to start and end in vulnerability network
                if network_node in [network.start, network.end]:
                    tree_node.val = 0
                    tree_node.command = 1
                    
                nodes.append(tree_node)   
        
        #Initialize connections for attack tree node
        # tnode
        for network_node in nodes:
            # vulNode
            for vulnerability in network_node.node.connections:
                #For upper layer
                if len(arg) == 0:
                    # tNode
                    for t in nodes:
                        if t.node is vulnerability:
                            network_node.connections.append(t)
                #For lower layer
                else:
                    # Privilege value is used here to decide what vulnerabilities an attacker can use for attack paths
                    print("Checking vulnerability:", (vulnerability.postcondition is not '') and arg[0] >= self.convert_condition_to_int(vulnerability.postcondition))
                    if (vulnerability.postcondition is not '') and arg[0] >= self.convert_condition_to_int(vulnerability.postcondition):
                        for t in nodes:
                            if t.node is vulnerability:
                                network_node.connections.append(t)      
        return None
    
    #Construct the attack tree
    def construct(self, network, val, *arg):
        nodes = []      # tNode/tVulNode
        history = []
        e = None
        self.topGate = orGate()
        self.preprocess(network, nodes, val, *arg)

        #For one vulnerability
        if len(nodes) < 4:
            a_gate = andGate()
            for node in nodes:
                a_gate.connections.append(node)
                
            self.topGate.connections.append(a_gate)
        #For more than one vulnerability
        else:
            for u in nodes:
                if u.node is network.end:
                    e = u
                if u.node is network.start:
                    self.topGate.connections.append(u)
            
            self.simplify(self.topGate, history, e)
            self.targetOut(self.topGate, e)
            self.foldgate(self.topGate)

    #Simplify the method
    def simplify(self, gate, history, target):
        tGate = []
        tGate.extend(gate.connections)
        value = 1
        if len(tGate) == 0:
            value = 0
        
        for item in tGate:    
            if (item is not target) and (item.t == "node"):
                a_gate = andGate()
                gate.connections.append(a_gate)
                gate.connections.remove(item)
                                          
                a_gate.connections.append(item)
                o_gate = orGate()                                      
                a_gate.connections.append(o_gate)
                
                for u in item.connections:
                    if u not in history:
                        o_gate.connections.append(u)
                       
                history.append(item)
                value = self.simplify(o_gate, history, target)
                history.pop()
                if len(o_gate.connections) < 1:
                    a_gate.connections.remove(o_gate)
                    if len(a_gate.connections) == 1 and value == 0:
                        gate.connections.append(item)
                        gate.connections.remove(a_gate)
                
                value = value * item.val
    
        return value
    
    def targetOut(self, rootGate, target):
        self.targetOutRecursive(rootGate, target)
        for gate in rootGate.connections:
            gate.connections.append(target)
        self.deleteEmptyGates(rootGate)        
        
    def deleteEmptyGates(self, gate):
        removedGates = []
        for node in gate.connections:
            if node.t in ['andGate', 'orGate']:
                if (len(node.connections) == 1) and (node.connections[0] == "removed"):
                    removedGates.append(node)
                else:
                    self.deleteEmptyGates(node)
                                
        for node in removedGates:
            gate.connections.remove(node)    
                
    def targetOutRecursive(self, gate, target):
        toChange = []
        for node in gate.connections:
            if node is target:
                if len(gate.connections) == 1:
                    del gate.connections[:]
                    gate.connections.append("removed")
                    break
                else:                    
                    toChange.append(node)                    
                    
            elif node.t in ['andGate', 'orGate']:
                self.targetOutRecursive(node, target)
        for node in toChange:
            gate.connections.remove(node)
            nothing = tNode('at-.')
            nothing.val = 1            
            gate.connections.append(nothing)
            
    #Fold gate with one child                
    def foldgate(self, gate):
        removedGates = []
        for node in gate.connections:
            if node.t in ['andGate', 'orGate']:
                self.foldgate(node)
                if len(node.connections) == 1:
                    gate.connections.extend(node.connections)
                    removedGates.append(node)                
        for node in removedGates:
            gate.connections.remove(node)
            
    def tPrintRecursive(self, gate):
        print(gate.name, '->',)
        for u in gate.connections:
            print(u.name)
        print()
        for u in gate.connections:
            if u.t in ['andGate', 'orGate']:
                self.tPrintRecursive(u)
    
    #Print tree
    def treePrint(self):
        self.tPrintRecursive(self.topGate)

    def convert_condition_to_int(self, condition):
        """
        Convert the string condition to integer.
        """
        if condition == "None":
            return 1
        elif condition == "User":
            return 2
        elif condition == "Root":
            return 3

   