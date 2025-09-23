"""
CREST Project 9: Automated security assessment for interconnected systems
Created by Mengmeng Ge
Modified by Moyang Feng
05/02/2020
This module constructs attack graph.
"""


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
        self.n = None
        #Store the Simulation value used in security analysis
        self.val = 0
        self.vuls = []
        self.type = None
        #Used to check whether the node is included in the attack path or not
        self.inPath = 0
        self.subnet = []
        self.mv3 = metrics_v3()
        
    def __str__(self):
        return self.name
    
               
class gVulNode(VulnerabilityNode):
    """
    Create attack graph vulnerability object.
    """
    def __init__(self, name):
        super(gVulNode, self).__init__(name)
        #Store the vulnerability node
        self.n = None
        #Store the Simulation value used in security analysis
        self.val = 0
        self.inPath = 0
        self.mv3 = metrics_v3()
        
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
        for u in [network.start, network.end] + network.nodes:
            if u is not None:
                #For vulnerability
                if type(u) is VulnerabilityNode:
                    gn = gVulNode('ag_' + str(u.name))
                    gn.privilege = u.privilege
                    # gn.mv2 = u.mv2
                #For node
                else:
                    gn = GraphNode('ag_' + str(u.name))
                        
                    #Assign default value to attacker node
                    if u.isStart == True:
                        gn.val = -1
                    else:
                        gn.val = val
                        
                    if u is not network.start and u is not network.end:
                        gn.type = u.type
                        
                        #for sub in u.subnet:
                            #gn.subnet.append(sub)                
                                                                             
                gn.n = u
                
                #Assign default value to start and end in network
                if u in [network.start, network.end]:
                    gn.val = -1
                    
                self.nodes.append(gn)
                #print(gn.name)


        #Initialize reachable_vulnerabilities for attack graph node   
        for u in self.nodes:       
            #print(u)
            for v in u.n.reachable_vulnerabilities:
                #For upper layer
                if len(arg) is 0:
                    for t in self.nodes:
                        if t.n.name == v.name:
                            #print("reachable_vulnerabilities:", t.name)
                            u.reachable_vulnerabilities.append(t)
                #For lower layer
                else:
                    if arg[0] >= v.privilege:
                        for t in self.nodes:
                            if t.n is v:
                                u.reachable_vulnerabilities.append(t)
        
        #Initialize start and end in attack graph   
        for u in self.nodes:
            if u.n is network.start:
                self.s = u    
            if u.n is network.end:
                self.e = u
        
        #Remove start and end from nodes in attack graph      
        if self.s is not None:
            self.nodes.remove(self.s)
        if self.e is not None:
            self.nodes.remove(self.e)           
    
    
    #Traverse graph                  
    def travelAgRecursive(self, u, e, path):
        val = 0
        for v in u.reachable_vulnerabilities:

            #Only include nodes with vulnerabilities in the path
            if v.inPath == 0 and (v.child != None or v.name == 'ag_attacker' or v is e):
                self.path.append(v)
                v.inPath = 1

                #Recursively traverse the path until to the end point
                if v is not e:
                    val += self.travelAgRecursive(v, e, self.path)
                else:
                    self.allpath.append(path[:])

                self.path.pop()
                v.inPath = 0

        return val

    #Traverse graph to get attack paths
    def travelAg(self): 
        self.allpath = []
        #Start to traverse from start point
        self.path = [self.s]
        #print(self.s.name, self.e.name)
        val = self.travelAgRecursive(self.s, self.e, self.path) #The value records recursion times

        return val   
    
    #Print graph
    def printAG(self):
        i = 0
        print('Printing attack graphs: ')
        for node in self.nodes:
            print("===============================================================")
            print(i ,': ', node.name, ', ', "number of reachable_vulnerabilities: ", len(node.reachable_vulnerabilities))
            for cons in node.reachable_vulnerabilities:
                #the target connects to end point, do not print end point
                if cons != self.e:
                    print(cons.name,)
            print
            i += 1
            
            if node.child != None and node is not self.s and node is not self.e and node.name != 'ag_attacker':
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
    
