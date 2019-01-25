from mininet.topo import Topo

class MyTopo( Topo ):

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        # Hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')

        # Add links
        self.addLink(s4, h1, 1, 1)
        self.addLink(s5, h2, 1, 1)
        self.addLink(s4, s1, 2, 1)
        self.addLink(s4, s2, 3, 1)
        self.addLink(s4, s3, 4, 1)
        self.addLink(s5, s1, 2, 2)
        self.addLink(s5, s2, 3, 2)
        self.addLink(s5, s3, 4, 2)



topos = { 'mytopo': ( lambda: MyTopo() ) }