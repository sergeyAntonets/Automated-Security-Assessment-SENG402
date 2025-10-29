
from Node import *
from Network import *
from Vulnerability import *
from math import *

class GraphNode(node):
    """
    Create attack graph node object.
    """
    def __init__(self, name):
        super(GraphNode, self).__init__(name)
        #Store the network node
        self.node = None
        #Store the Simulation value used in security analysis
        self.val = 0
        self.vuls = []
        self.type = None
        #Used to check whether the node is included in the attack path or not
        self.inPath = 0
        self.subnet = []
        # self.mv3 = metrics_v3()
        
    def __str__(self):
        return self.name
    
               
class gVulNode(VulnerabilityNode):
    """
    Create attack graph vulnerability object.
    """
    def __init__(self, name):
        super(gVulNode, self).__init__(name)
        #Store the vulnerability node
        self.node = None
        #Store the Simulation value used in security analysis
        self.val = 0
        # Flag to check if the node is in the current traversal path
        self.inPath = 0
        # self.mv3 = metrics_v3()
        
    def __str__(self):
        return self.name
                              

class AttackGraph(Network):
    """
    Create attack graph.
    """
    
    #Construct the attack graph
    def __init__(self, network, val, *arg):
        super(AttackGraph, self).__init__()        
        self.path = [] 
        #Store all possible paths from start to end
        self.allpath = []
        self.isAG = 1
        self.subnets = network.subnets  #All subnets in the network
        self.vuls = network.vuls        #All vuls in the network
                
        #Instantiate nodes in attack graph using network info
        for node in [network.start, network.end] + network.nodes:
            if node is not None:
                #For vulnerability
                if type(node) is VulnerabilityNode:
                    graph_node= gVulNode('ag_' + str(node.name))
                    graph_node.privilege = node.privilege
                    # graph_node.mv2 = node.mv2
                #For node
                else:
                    graph_node= GraphNode('ag_' + str(node.name))
                        
                    #Assign default value to attacker node
                    if node.isStart == True:
                        graph_node.val = -1
                    else:
                        graph_node.val = val
                        
                    if node is not network.start and node is not network.end:
                        graph_node.type = node.type
                        
                        #for sub in node.subnet:
                            #graph_node.subnet.append(sub)                
                                                                             
                graph_node.node = node
                
                #Assign default value to start and end in network
                if node in [network.start, network.end]:
                    graph_node.val = -1
                    
                self.nodes.append(graph_node)
                #print(graph_node.name)


        #Initialize connections for attack graph node based on network connections
        for node in self.nodes:       
            #print(u)
            for v in node.node.connections:
                # For upper layer (no privilege check)
                if len(arg) == 0:
                    for t in self.nodes:
                        if t.node.name == v.name:
                            #print("connections:", t.name)
                            node.connections.append(t)
                # For lower layer (with privilege check)
                else:
                    if arg[0] >= v.privilege:
                        for t in self.nodes:
                            if t.node is v:
                                node.connections.append(t)
        
        #Initialize start and end in attack graph   
        for node in self.nodes:
            if node.node is network.start:
                self.start = node    
            if node.node is network.end:
                self.e = node
        
        #Remove start and end from nodes in attack graph      
        if self.start is not None:
            self.nodes.remove(self.start)
        if self.e is not None:
            self.nodes.remove(self.e)           
    
    
    #Traverse graph recursively to find all attack paths
    def travelAgRecursive(self, node, e, path):
        val = 0
        for v in node.connections:

            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                self.path.append(v)
                v.inPath = 1

                #Recursively traverse the path until to the end point
                if v is not e:
                    val += self.travelAgRecursive(v, e, self.path)
                else:
                    # When the end is reached, add the current path to allpath
                    self.allpath.append(path[:])

                self.path.pop()
                v.inPath = 0

        return val

    #Traverse graph to get attack paths
    def travelAg(self): 
        self.allpath = []
        #Start to traverse from start point
        self.path = [self.start]
        #print(self.start.name, self.e.name)
        val = self.travelAgRecursive(self.start, self.e, self.path) #The value records recursion times

        return val   
    
    #Print graph
    def printAG(self):
        i = 0
        print('Printing attack graphs: ')
        for node in self.nodes:
            print("===============================================================")
            print(i ,': ', node.name, ', ', "number of connections: ", len(node.connections))
            for cons in node.connections:
                #the target connects to end point, do not print end point
                if cons != self.e:
                    print(cons.name,)
            print
            i += 1
            
            if node.child != None and node is not self.start and node is not self.e and node.name != 'ag_attacker':
                print("attack tree for " + node.name, " :")
                node.child.treePrint()
        
        return None
    
    #Print attack paths
    def printPath(self):
        print('Printing all attack paths: ')
        for path in self.allpath:
            print("--------------------------------------------------")
            for node in path:
                print(node.name)
            print("--------------------------------------------------")
        return None
    
    #Calculate attack paths
    def calcPath(self):
        return self.travelAg()
    
