from collections import deque
import logging

__author__ = 'rragan'

__version__ = '2014.5.09.1'

"""
5/09/14 - start
"""

class Edge(object):
    def __init__(self, src, dest):
        self.src = src
        self.dest = dest
    def getSource(self):
        return self.src
    def getDestination(self):
        return self.dest
    def __str__(self):
        return str(self.src) + '->' + str(self.dest)

class WeightedEdge(Edge):
    def __init__(self, src, dest, weight = 1.0):
        self.src = src
        self.dest = dest
        self.weight = weight
    def getWeight(self):
        return self.weight
    def __str__(self):
        return str(self.src) + '->(' + str(self.weight) + ')'\
            + str(self.dest)

class Digraph(object):
    def __init__(self):
        self.nodes = set([])
        self.edges = {}
    def addNode(self, node):
        if node in self.nodes:
            raise ValueError('Duplicate node')
        else:
            self.nodes.add(node)
            self.edges[node] = []
    def addEdge(self, edge):
        src = edge.getSource()
        dest = edge.getDestination()
        if not(src in self.nodes and dest in self.nodes):
            raise ValueError('Node not in graph')
        self.edges[src].append(dest)
    def childrenOf(self, node):
        return self.edges[node]
    def hasNode(self, node):
        return node in self.nodes
    def __str__(self):
        res = ''
        for k in self.edges:
            for d in self.edges[k]:
                res = res + str(k) + '->' + str(d) + '\n'
        return res[:-1]

class Graph(Digraph):
    def __init__(self):
        Digraph.__init__(self)
    def addEdge(self, edge):
        Digraph.addEdge(self, edge)
        rev = Edge(edge.getDestination(), edge.getSource())
        Digraph.addEdge(self, rev)

class NetworkGraph(Graph):
    def __init__(self, seed, depth=None):
        self.logger = logging.getLogger('nexusnetwork.NetworkGraph')
        self.logger.debug("Instantiating NetworkGraph object")
        self.seed = list(seed)
        self.depth = depth
        Graph.__init__(self)
        self.to_search = deque(self.seed)
    def add_to_queue(self, node):
        if node not in self.to_search:
            self.to_search.appendleft(node)
    def get_next_node(self):
        self.to_search.pop()

