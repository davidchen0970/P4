import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField, XBitField, bind_layers

class DupLayer(Packet):
    name = "dup_id"
    fields_desc = [
        BitField("isDup", 0, 8),
        XBitField("ackNum", 0, 8),
    ]

class cpuInfoLayer(Packet):
    name = "cpu_info"
    fields_desc = [
        BitField("ackNum", 0, 8),
        XBitField("packetNum", 0, 8),
    ]
    
bind_layers(Ether, DupLayer, type=0x1212)
bind_layers(Ether, cpuInfoLayer, type=0x1213)
bind_layers(Ether, cpuInfoLayer, type=0x1214)

class myController(object):

    def __init__(self):
        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.connect_to_switches()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            print "p4switch:", p4switch, "thrift_port:", thrift_port
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port) 	

    def recv_msg_cpu(self, pkt):
        print "interface:", pkt.sniffed_on
        print "summary:", pkt.summary()
        if DupLayer in pkt:
            my_layer = pkt[DupLayer]
            print "DupLayer isDup :", my_layer.isDup
            print "DupLayer ackNum:", my_layer.ackNum
        if cpuInfoLayer in pkt:
            my_layer = pkt[cpuInfoLayer]
            print "DupLayer ackNum   :", my_layer.ackNum
            print "DupLayer packetNum:", my_layer.packetNum
      
    def run_cpu_port_loop(self):
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.recv_msg_cpu)
        
if __name__ == "__main__":
    controller = myController()
    controller.run_cpu_port_loop()
