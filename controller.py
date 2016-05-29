__author__ = 'rragan'

__version__ = '2014.5.10.1'

"""
5/10/14 - start
"""

class Controller(object):
    def __init(self):
        pass

    def connect_to_nodes(self, nodes, *args, **kwargs):
        """

        @param nodes:
        @param args:
        @param kwargs:

        """
        if isinstance(nodes, str): nodes = [nodes]

    def set_credentials(self, credentials):
        """

        @param credentials:
        
        """
        assert isinstance(credentials, dict)