import nnpy
import struct
from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
from scapy.all import Ether, sniff, Packet, BitField, XBitField, bind_layers
import os
from collections import deque, defaultdict
import math
import time

class DupLayer(Packet):
    name = "dup_id"
    fields_desc = [
        BitField("name"         , 0, 2),
        BitField("isDup"        , 0, 6),
        BitField("ackNum"       , 0, 8),
        BitField("packetNum"    , 0, 8),
        BitField("CPUackNum"    , 0, 8),
        BitField("CPUpacketNum" , 0, 8),
        BitField("CPUvalidNum"  , 0, 8),
        BitField("isRCV"        , 0, 8),
   ]

bind_layers(Ether, DupLayer, type=0x1212)

class myController(object):

    def __init__(self):
        self.topo = Topology(db="topology.db")
        self.controllers = {}
        self.connect_to_switches()
        self.redundancy_ratio = 1
        self.add_table_entries(self.redundancy_ratio)
        self.switchPacketNum = 250
        self.s1_packetNum = deque(maxlen=self.switchPacketNum + 1)
        self.s2_packetNum = deque(maxlen=self.switchPacketNum + 1)
        self.s1_red_times = deque(maxlen=self.switchPacketNum)
        self.s2_red_times = deque(maxlen=self.switchPacketNum)
        self.s1_validNum = deque(maxlen=self.switchPacketNum + 1)
        self.s2_validNum = deque(maxlen=self.switchPacketNum + 1)
        self.s1_ackList = deque(maxlen=self.switchPacketNum)
        self.s2_ackList = deque(maxlen=self.switchPacketNum)
        self.packet_count = defaultdict(int)
        self.start_time = time.time()
        self.userAcc = 95
        self.predicted_arrival_ratios = -1
        self.isOverLoading = False
        self.protectedTime = 0

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            print("p4switch:", p4switch, "thrift_port:", thrift_port)
            self.controllers[p4switch] = SimpleSwitchAPI(thrift_port)
    
    def add_table_entries(self, value):
        value_str = '0x{:02X}'.format(value)
        for p4switch, controller in self.controllers.items():
            controller.table_clear('dup_rate_table')
            controller.table_add('dup_rate_table', 'insert_dupHeader', ['0x0800'], [value_str])
            controller.table_add('dup_rate_table', 'insert_dupHeader', ['0x0808'], [value_str])

    def recv_msg_cpu(self, pkt):
        if DupLayer in pkt:
            src_dst = pkt.summary()
            current_time = time.time()
            my_layer = pkt[DupLayer]

            if src_dst in ["00:01:0a:00:01:01 > 00:01:0a:00:01:01 (0x1212) / DupLayer / Raw"]:
                my_layer = pkt[DupLayer]
            
            elif src_dst in ["00:01:0a:00:01:01 > 00:00:0a:00:02:01 (0x1212) / DupLayer / Raw"]:
                my_layer = pkt[DupLayer]
                self.update_deques(my_layer, 's2')

            elif src_dst in ["00:01:0a:00:02:01 > 00:00:0a:00:01:01 (0x1212) / DupLayer / Raw"]:
                my_layer = pkt[DupLayer]
                self.update_deques(my_layer, 's1')

            elif src_dst in ["00:01:0a:00:02:01 > 00:01:0a:00:02:01 (0x1212) / DupLayer / Raw"]:
                my_layer = pkt[DupLayer]

            # Increment packet count
            if(my_layer.isDup > 0):
                self.packet_count[src_dst] += my_layer.isDup
            else:
                self.packet_count[src_dst] += 1
            # Update every second
            if current_time - self.start_time >= 0.5 and len(self.s1_validNum) >= 100:
                self.protectedTime -= (current_time - self.start_time)
                self.start_time = current_time
                self.display_packet_table()

    def update_deques(self, my_layer, switch):
        if switch == 's1':
            self.s1_packetNum.append(my_layer.CPUpacketNum)
            self.s1_red_times.append(my_layer.isDup)
            self.s1_validNum.append(my_layer.CPUvalidNum)
            self.s1_ackList.append(my_layer.CPUackNum)
        elif switch == 's2':
            self.s2_packetNum.append(my_layer.CPUpacketNum)
            self.s2_red_times.append(my_layer.isDup)
            self.s2_validNum.append(my_layer.CPUvalidNum)
            self.s2_ackList.append(my_layer.CPUackNum)

    def calculate_diff(self, data_list):
        data_list = list(data_list)
        if len(data_list) == 0:
            return 0
        total_diff = 0
        prev = data_list[0]
        for current in data_list[1:]:
            if current >= prev:
                diff = current - prev
            else:
                diff = (255 - prev) + current + 1
            total_diff += diff
            prev = current
        return total_diff
    
    def calculate_avg(self, data_list):
        data_list = list(data_list)
        if len(data_list) == 0:
            return 0
        total_avg = 0.0
        for current in data_list:
            total_avg += current
        total_avg = total_avg / len(data_list)
        return total_avg

    def calculate_loss(self, packetNum_total, red_times_avg, ack_diff):
        if ack_diff * red_times_avg > 0:
            return ((ack_diff * red_times_avg - packetNum_total)/ (ack_diff * red_times_avg))
        return 0

    def calculate_arrival(self, validNum_total, ack_diff):
        if ack_diff != 0:
            return min(1, float(validNum_total) / float(ack_diff))
        return 0

    def get_min_redundancy(self):
        # Define a function to calculate arrival ratio for a given target redundancy
        def predict_arrival(loss_avg, node_num, target_redundancy):
            return min(1, pow(1 - pow(loss_avg, target_redundancy), node_num))

        # Calculate average loss
        loss_avg = (self.s1_loss + self.s2_loss) / 2

        # Define the range for target redundancy to check
        redundancies = [0, 1, 2, 3, 4]
        
        for target_redundancy in redundancies:
            # Predict the arrival ratio for each target redundancy
            arrival_ratio = predict_arrival(loss_avg, 2, target_redundancy) * 100
            # Check if it meets the requirement
            if arrival_ratio >= self.userAcc:
                return target_redundancy

        # If no redundancy level meets the requirement, return None or some default value
        return 0


    def display_packet_table(self):
        s1_packetNum_total = self.calculate_diff(self.s1_packetNum)
        s1_red_times_avg = self.calculate_avg(self.s1_red_times)
        s1_validNum_total = self.calculate_diff(self.s1_validNum)
        s1_ack_diff = self.calculate_diff(self.s1_ackList) + 1

        s2_packetNum_total = self.calculate_diff(self.s2_packetNum)
        s2_red_times_avg = self.calculate_avg(self.s2_red_times)
        s2_validNum_total = self.calculate_diff(self.s2_validNum)
        s2_ack_diff = self.calculate_diff(self.s2_ackList) + 1

        self.s1_loss = self.calculate_loss(s1_packetNum_total, s1_red_times_avg, s1_ack_diff)
        self.s2_loss = self.calculate_loss(s2_packetNum_total, s2_red_times_avg, s2_ack_diff)
        
        s1_arrival = self.calculate_arrival(s1_validNum_total, s1_ack_diff)
        s2_arrival = self.calculate_arrival(s2_validNum_total, s2_ack_diff)

        arrival_product = s1_arrival * s2_arrival

        # Print existing stats
        os.system('clear')
        os.system('clear')

        # Retain previous src_dst entries and update counts
        current_src_dst = set(self.packet_count.keys())
        sorted_packet_counts = sorted(self.packet_count.items(), key=lambda x: x[0])

        # Retrieve previous counts from a stored history or initialize if not present
        if not hasattr(self, 'prev_packet_count'):
            self.prev_packet_count = defaultdict(int)

        # Update the counts, and include src_dst that have not appeared in the current update
        for src_dst in self.prev_packet_count:
            if src_dst not in current_src_dst:
                sorted_packet_counts.append((src_dst, 0))

        # Update previous packet count records
        self.prev_packet_count.update(self.packet_count)

        # Sort again after adding missing src_dst
        sorted_packet_counts.sort(key=lambda x: x[0])

        # Print packet count per second
        print("+------------------------------------------------------------------+------------------------+")
        print("|                          Packet Summary                          |        Count/Second    |")
        print("+------------------------------------------------------------------+------------------------+")
        for src_dst, count in sorted_packet_counts:
            print("| {:<64} | {:<22} |".format(src_dst, count))
        print("+------------------------------------------------------------------+------------------------+")

        print("+----------------+---------------+---------------+----------------+---------------+")
        print("|     Switch     |   PacketNum   |   DUP Times   |  Loss/Arrival  |      ACK      |")
        print("+----------------+---------------+---------------+----------------+---------------+")
        print("| s1             | {:<13.2f} | {:<13.2f} | {:<13.2f}  | {:<13.2f} |".format(s1_packetNum_total, s1_red_times_avg, self.s1_loss * 100 , s1_ack_diff))
        print("| s1 Valid Num   | {:<13.2f} |               | {:<13.2f}  |               |".format(s1_validNum_total, s1_arrival))
        print("+----------------+---------------+---------------+----------------+---------------+")
        print("| s2             | {:<13.2f} | {:<13.2f} | {:<13.2f}  | {:<13.2f} |".format(s2_packetNum_total, s2_red_times_avg, self.s2_loss * 100 , s2_ack_diff))
        print("| s2 Valid Num   | {:<13.2f} |               | {:<13.2f}  |               |".format(s2_validNum_total, s2_arrival))
        print("+----------------+---------------+---------------+----------------+---------------+")
        print("| Arrival Ratio  | {:<12.2f}% |               |   Loss Ratio   | {:<12.2f}% |".format(arrival_product * 100, (self.s2_loss + self.s1_loss) * 50 ))
        print("+----------------+---------------+---------------+----------------+---------------+")

        # Reset packet counts
        self.packet_count = defaultdict(int)

        # Save the current packet counts for the next call
        self.prev_packet_count.update(self.packet_count)
        
        self.predict_arrival_ratios()


    def predict_arrival_ratios(self):
        s1_validNum_total = self.calculate_diff(self.s1_validNum)
        s1_ack_diff = self.calculate_diff(self.s1_ackList)
        s2_validNum_total = self.calculate_diff(self.s2_validNum)
        s2_ack_diff = self.calculate_diff(self.s2_ackList)

        s1_arrival = self.calculate_arrival(s1_validNum_total, s1_ack_diff)
        s2_arrival = self.calculate_arrival(s2_validNum_total, s2_ack_diff)
        red_times_avg = (self.calculate_avg(self.s1_red_times) + self.calculate_avg(self.s2_red_times)) / 2
        arrival_product = s1_arrival * s2_arrival
        loss_avg = (self.s1_loss + self.s2_loss) / 2

        def predict_arrival(loss_avg, node_num, target_redundancy):
            return min(1, pow(1 - pow((loss_avg),(target_redundancy)),node_num))
    
        def clear_record():
            self.s1_packetNum.clear()
            self.s2_packetNum.clear()
            self.s1_red_times.clear()
            self.s2_red_times.clear()
            self.s1_validNum.clear()
            self.s2_validNum.clear()
            self.s1_ackList.clear()
            self.s2_ackList.clear()


        arrival_ratio_none = predict_arrival(loss_avg, 2, 1)
        arrival_ratio_once = predict_arrival(loss_avg, 2, 2)
        arrival_ratio_twice = predict_arrival(loss_avg, 2, 3)
        arrival_ratio_thrice = predict_arrival(loss_avg, 2, 4)

        # Print the header of the table
        print("+------------------------+--------------------+")
        print("| Redundancy             | Arrival Ratio (%)  |")
        print("+------------------------+--------------------+")

        # Print each row with formatted values
        print("| Current Arrival Ratio  | {:<17.2f}% |".format(arrival_product * 100))
        print("| After 0 Redundancy     | {:<17.2f}% |".format(arrival_ratio_none * 100))
        print("| After 1 Redundancy     | {:<17.2f}% |".format(arrival_ratio_once * 100))
        print("| After 2 Redundancies   | {:<17.2f}% |".format(arrival_ratio_twice * 100))
        print("| After 3 Redundancies   | {:<17.2f}% |".format(arrival_ratio_thrice * 100))
        print("+------------------------+--------------------+")

        # Check if the predicted arrival ratios indicate overload
        if arrival_product + 0.02 < self.predicted_arrival_ratios and self.predicted_arrival_ratios != -1:
            self.isOverLoading = True
        else:
            self.isOverLoading = False

        # Print additional information for debugging
        print("+---------------------------------------------------------+")
        print("| arrival_ratio_none             | {:<22.2f} |".format(arrival_product))
        print("| self.predicted_arrival_ratios  | {:<22.2f} |".format(self.predicted_arrival_ratios))
        print("| self.protectedTime             | {:<22.2f} |".format(self.protectedTime))
        print("+---------------------------------------------------------+")


        min_redundancy = self.get_min_redundancy()
        if( self.protectedTime > 0) :
            self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, self.redundancy_ratio)
            print("| Minimum redundancy required to exceed userAcc ({:.2f}%): {:<2} (Detected Overloading)|".format(self.userAcc, self.redundancy_ratio))
            return 
        
        if self.isOverLoading == True:
            print("| Minimum redundancy required to exceed userAcc ({:.2f}%): {:<2} (Detected Overloading)|".format(self.userAcc, self.redundancy_ratio))
            self.add_table_entries(max(1,self.redundancy_ratio - 1))
            self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, max(1,self.redundancy_ratio - 1))
            self.protectedTime = 2
            self.redundancy_ratio = 1
            clear_record()
            return 
        
        if min_redundancy != 0:
            print("| Minimum redundancy required to exceed userAcc ({:.2f}%): {:<2} |".format(self.userAcc, min_redundancy))
            self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, min_redundancy)
            if(min_redundancy != self.redundancy_ratio):
                self.add_table_entries(min_redundancy)
                self.redundancy_ratio = min_redundancy
        else:
            print("| No redundancy level meets the userAcc requirement. |")
            self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, 1)
            # if(self.redundancy_ratio != 1):
            self.add_table_entries(1)
            self.redundancy_ratio = 1
            clear_record()
            

        # if min_redundancy is not None and(self.protectedTime <= 0):
        #     self.protectedTime = 0
        #     if self.isOverLoading == False:
        #         print("| Minimum redundancy required to exceed userAcc ({:.2f}%): {:<2} |".format(self.userAcc, min_redundancy - 1))
        #         if(min_redundancy != self.redundancy_ratio):
        #             self.add_table_entries(min_redundancy)
        #         self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, min_redundancy)
        #     else:
        #         print("| Minimum redundancy required to exceed userAcc ({:.2f}%): {:<2} (Detected Overloading)|".format(self.userAcc, min_redundancy - 2))
        #         if((min_redundancy - 1) != self.redundancy_ratio):
        #             self.add_table_entries(min_redundancy - 1)
        #         self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, min_redundancy - 1)
        # else:
        #     if( self.protectedTime > 0) :
        #         return 
        #     print("| No redundancy level meets the userAcc requirement. System use minimum redundancy: 0. |")
        #     self.add_table_entries(1)
        #     self.predicted_arrival_ratios = predict_arrival(loss_avg, 2, 1)
        #     self.redundancy_ratio = 1
        #     self.protectedTime = 10

    def run_cpu_port_loop(self):
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.recv_msg_cpu)

if __name__ == "__main__":
    controller = myController()
    controller.run_cpu_port_loop()
 
