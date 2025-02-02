import socket
import threading
import time
import argparse
import NetTask
import psutil
import utils
import AlertFlow

class NMSAgent:
    def __init__(self, server_ip, udp_port, tcp_port):
        self.agent_id = socket.gethostname()
        self.server_ip = server_ip
        self.udp_port = udp_port
        self.tcp_port = tcp_port

        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(('0.0.0.0', 6969)) 
        self.netTaskProtocol = NetTask.NetTaskProtocol(self.udp_socket, self.server_ip, self.udp_port, self.agent_id)

        self.tasks_seq_number = {}
        self.acks_seq_number = {}
        self.current_seq_num = 0
        self.seq_num_lock = threading.Lock()

        self.last_task_seq_num = 0

        self.iperf_server_running_udp = 0
        self.iperf_server_running_tcp = 0

        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
        

    def start(self):
        self.connect_tcp()

        register_seq_num = self.netTaskProtocol.registerSYN()
        self.acks_seq_number[register_seq_num] = 0

        register_retransmission_thread = threading.Thread(target=self.register_retransmission, args=(register_seq_num,)) 
        register_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
        register_retransmission_thread.start()
        
        try:
            while True:
                data, addr = self.udp_socket.recvfrom(100) # Always udp_port 6000
                packet = NetTask.NetTaskGenericPacket.from_bytes(data) # Decode bytes -> Packet

                if packet.packet_type == 1: # ACK
                    message = NetTask.NetTaskACKPacket.from_bytes(data)
                    self.acks_seq_number[message.seq_num] = 1
                    message.print_packet(addr[0], addr[1])

                    if message.seq_num == register_seq_num:
                        print("Registration complete.\n---------")

                if packet.packet_type == 2: #TASK
                    message = NetTask.NetTaskGenericTASKPacket.from_bytes(data)

                    if message.seq_num not in self.tasks_seq_number: #If this is a new task, not retransmission nor duplicate
                        if message.seq_num > self.last_task_seq_num:
                            self.last_task_seq_num = message.seq_num #update the seq number of the last recieved task

                    tasks_thread = threading.Thread(target=self.recieveTasks, args=(message, data, addr[0], addr[1])) 
                    tasks_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    tasks_thread.start() 
                    


        except KeyboardInterrupt:
            self.cleanup()

    def connect_tcp(self):
        try:
            self.tcp_socket.connect((self.server_ip, self.tcp_port))
            print(f"TCP connection established with server at {self.server_ip}:{self.tcp_port}")
        except Exception as e:
            print(f"Failed to connect to server: {e}")

    def send_alert_message(self, seq_num: int, task_type: int, task_threshold: int, metric_value: int):
        try:
            alertPacket = AlertFlow.AlertFlowPacket(seq_num, task_type, task_threshold, metric_value)
            self.tcp_socket.sendall(alertPacket.to_bytes())
            print(f"Sent TCP Alert message to {self.server_ip}")
        except Exception as e:
            print(f"Failed to send TCP message: {e}")

    def register_retransmission(self, register_seq_num:int):
        max_retransmission_retries = 5

        while (max_retransmission_retries > 0):
            time.sleep(4)
            if self.acks_seq_number[register_seq_num] != 1:
                print("Timeout exceeded for register's ACK, retransmiting...\n")
                self.netTaskProtocol.registerSYN()
                max_retransmission_retries-=1
            else: 
                max_retransmission_retries = -1
        
        if max_retransmission_retries == 0: 
            print("Maximum retransmission tries were exceeded for registering.\n")
        

    def recieveTasks(self, packet_task: NetTask.NetTaskGenericTASKPacket, data: bytes, source_ip: int, source_port: int):

        if (packet_task.task_type == 0 or packet_task.task_type == 1): #CPU or RAM task packet
            packet_CpuRam = NetTask.NetTaskTASKcpuramPacket.from_bytes(data)
            packet_CpuRam.print_packet(source_ip, source_port)

            if packet_CpuRam.seq_num in self.tasks_seq_number:
                print("^ DUPLICATE ^") 
            
            self.netTaskProtocol.sendACK(packet_CpuRam.seq_num)

            if packet_CpuRam.task_type == 0:
                if packet_CpuRam.seq_num not in self.tasks_seq_number:
                    udp_thread = threading.Thread(target=self.executeCPUTask, args=(packet_CpuRam,)) 
                    udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    udp_thread.start() 

            if packet_CpuRam.task_type == 1:
                if packet_CpuRam.seq_num not in self.tasks_seq_number:
                    udp_thread = threading.Thread(target=self.executeRAMTask, args=(packet_CpuRam,)) 
                    udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    udp_thread.start()

        elif (packet_task.task_type == 4):
            packet_interface = NetTask.NetTaskTASKinterfacePacket.from_bytes(data)
            packet_interface.print_packet(source_ip, source_port)

            if packet_interface.seq_num in self.tasks_seq_number:
                print("^ DUPLICATE ^")
            
            self.netTaskProtocol.sendACK(packet_interface.seq_num)

            if packet_interface.seq_num not in self.tasks_seq_number:
                udp_thread = threading.Thread(target=self.executeInterfaceTask, args=(packet_interface,)) 
                udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                udp_thread.start() 
        
        elif (packet_task.task_type == 3):
            packet_latency = NetTask.NetTaskTASKlatencyPacket.from_bytes(data)
            packet_latency.print_packet(source_ip, source_port)

            if packet_latency.seq_num in self.tasks_seq_number:
                print("^ DUPLICATE ^")
            
            self.netTaskProtocol.sendACK(packet_latency.seq_num)

            if packet_latency.seq_num not in self.tasks_seq_number:
                udp_thread = threading.Thread(target=self.executeLatencyTask, args=(packet_latency,)) 
                udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                udp_thread.start() 

        elif (packet_task.task_type == 6 or packet_task.task_type == 5):
            packet_jitter_packet_loss = NetTask.NetTaskTASKjitterpacketlossPacket.from_bytes(data)
            packet_jitter_packet_loss.print_packet(source_ip, source_port)

            if packet_jitter_packet_loss.seq_num in self.tasks_seq_number:
                print("^ DUPLICATE ^")
            
            self.netTaskProtocol.sendACK(packet_jitter_packet_loss.seq_num)
                                                                                   
            if packet_jitter_packet_loss.seq_num not in self.tasks_seq_number:
                if (packet_jitter_packet_loss.task_mode == 1 and self.iperf_server_running_udp == 0) or (packet_jitter_packet_loss.task_mode == 0):
                    #if this agent isnt running an iperf server yet
                    udp_thread = threading.Thread(target=self.executejitterpacketlossTask, args=(packet_jitter_packet_loss,)) 
                    udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    udp_thread.start() 
        
        elif (packet_task.task_type == 2):
            packet_throughput = NetTask.NetTaskTASKbandwidthPacket.from_bytes(data)
            packet_throughput.print_packet(source_ip, source_port)

            if packet_throughput.seq_num in self.tasks_seq_number:
                print("^ DUPLICATE ^")
            
            self.netTaskProtocol.sendACK(packet_throughput.seq_num)

            if packet_throughput.seq_num not in self.tasks_seq_number:
                if (packet_throughput.task_mode == 1 and self.iperf_server_running_udp == 0 and packet_throughput.task_type == 0) or (packet_throughput.task_mode == 0) or (packet_throughput.task_mode == 1 and self.iperf_server_running_tcp == 0 and packet_throughput.task_transport_type == 1):
                    #if this agent isnt running an iperf server yet
                    udp_thread = threading.Thread(target=self.executethroughputTask, args=(packet_throughput,)) 
                    udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    udp_thread.start() 
            
    def executethroughputTask(self, packet_throughput: NetTask.NetTaskTASKbandwidthPacket):
        self.tasks_seq_number[packet_throughput.seq_num] = 1
        if packet_throughput.task_mode == 1 and packet_throughput.task_transport_type == 1 and self.iperf_server_running_tcp == 0: # is server
            self.iperf_server_running_tcp = 1 # iperf server is running from now on in this agent
        
        if packet_throughput.task_mode == 1 and packet_throughput.task_transport_type == 0 and self.iperf_server_running_udp == 0: # is server
            self.iperf_server_running_udp = 1 # iperf server is running from now on in this agent

        periodically_do = 3
        while (periodically_do > 0):
            periodically_do-=1

            dest_ip = utils.AgentUtils.ints_to_ip(packet_throughput.task_server_ip_1, packet_throughput.task_server_ip_2, packet_throughput.task_server_ip_3, packet_throughput.task_server_ip_4)
            metric_value = utils.AgentUtils.execute_task(packet_throughput.task_mode, packet_throughput.task_duration, dest_ip, packet_throughput.task_type)

            if packet_throughput.task_mode == 0: # only the client sends metrics
                # Use lock to safely read and update current_seq_num
                with self.seq_num_lock:
                    # Read and use current_seq_num in the max function
                    seq_num_to_use = max(packet_throughput.seq_num, self.current_seq_num, self.last_task_seq_num)

                    # Update current_seq_num and other variables
                    metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_throughput.task_type, packet_throughput.task_server_ip_1, packet_throughput.task_server_ip_2, packet_throughput.task_server_ip_3, packet_throughput.task_server_ip_4, round(metric_value))
                    self.current_seq_num = metric_seq_num
                    self.acks_seq_number[metric_seq_num] = 0

                max_retransmission_tries = 5
                while (max_retransmission_tries > 0):
                    time.sleep(4)
                    if self.acks_seq_number[metric_seq_num] != 1:
                        print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_throughput.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmiting...")
                        self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_throughput.task_type, packet_throughput.task_server_ip_1, packet_throughput.task_server_ip_2, packet_throughput.task_server_ip_3, packet_throughput.task_server_ip_4, round(metric_value))
                        max_retransmission_tries-=1
                    else: 
                        max_retransmission_tries = -1
                
                if max_retransmission_tries == 0:
                    print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_throughput.task_type)} task.")

            else:
                break
            
            time.sleep(packet_throughput.task_frequency)

    def executejitterpacketlossTask(self, packet_jitter_packet_loss: NetTask.NetTaskTASKjitterpacketlossPacket):
        self.tasks_seq_number[packet_jitter_packet_loss.seq_num] = 1
        if packet_jitter_packet_loss.task_mode == 1 and self.iperf_server_running_udp == 0: # is server
            self.iperf_server_running_udp = 1 # iperf server is running from now on in this agent

        periodically_do = 3
        while (periodically_do > 0):
            periodically_do-=1

            dest_ip = utils.AgentUtils.ints_to_ip(packet_jitter_packet_loss.task_server_ip_1, packet_jitter_packet_loss.task_server_ip_2, packet_jitter_packet_loss.task_server_ip_3, packet_jitter_packet_loss.task_server_ip_4)
            metric_value = utils.AgentUtils.execute_task(packet_jitter_packet_loss.task_mode, packet_jitter_packet_loss.task_duration, dest_ip, packet_jitter_packet_loss.task_type)
            
            if packet_jitter_packet_loss.task_mode == 0: # only the client sends metrics
                # Use lock to safely read and update current_seq_num
                with self.seq_num_lock:
                    # Read and use current_seq_num in the max function
                    seq_num_to_use = max(packet_jitter_packet_loss.seq_num, self.current_seq_num, self.last_task_seq_num)

                    # Update current_seq_num and other variables
                    metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_jitter_packet_loss.task_type, packet_jitter_packet_loss.task_server_ip_1, packet_jitter_packet_loss.task_server_ip_2, packet_jitter_packet_loss.task_server_ip_3, packet_jitter_packet_loss.task_server_ip_4, round(metric_value))
                    self.current_seq_num = metric_seq_num
                    self.acks_seq_number[metric_seq_num] = 0

            if (packet_jitter_packet_loss.task_threshold < metric_value):
                self.send_alert_message(metric_seq_num, packet_jitter_packet_loss.task_type, packet_jitter_packet_loss.task_threshold, metric_value)

                max_retransmission_tries = 5
                while (max_retransmission_tries > 0):
                    time.sleep(4)
                    if self.acks_seq_number[metric_seq_num] != 1:
                        print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_jitter_packet_loss.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmiting...")
                        self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_jitter_packet_loss.task_type, packet_jitter_packet_loss.task_server_ip_1, packet_jitter_packet_loss.task_server_ip_2, packet_jitter_packet_loss.task_server_ip_3, packet_jitter_packet_loss.task_server_ip_4, round(metric_value))
                        max_retransmission_tries-=1
                    else: 
                        max_retransmission_tries=-1
                
                if max_retransmission_tries == 0:
                    print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_jitter_packet_loss.task_type)} task.")

            
            time.sleep(packet_jitter_packet_loss.task_frequency)


    def executeCPUTask(self, packet_Cpu: NetTask.NetTaskTASKcpuramPacket):
        self.tasks_seq_number[packet_Cpu.seq_num] = 1

        periodically_do = 3
        while (periodically_do > 0):
            periodically_do-=1
            cpu_usage = psutil.cpu_percent(packet_Cpu.frequency) 
            print(f"Current CPU Usage: {cpu_usage}%") 

            # Use lock to safely read and update current_seq_num
            with self.seq_num_lock:
                # Read and use current_seq_num in the max function
                seq_num_to_use = max(packet_Cpu.seq_num, self.current_seq_num, self.last_task_seq_num)

                # Update current_seq_num and other variables
                metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_Cpu.task_type, 0, 0, 0, 0, round(cpu_usage))
                self.current_seq_num = metric_seq_num
                self.acks_seq_number[metric_seq_num] = 0

            if (packet_Cpu.task_threshold < cpu_usage):
                self.send_alert_message(metric_seq_num, packet_Cpu.task_type, packet_Cpu.task_threshold, round(cpu_usage))

            max_retransmission_tries = 5
            while (max_retransmission_tries > 0):
                time.sleep(4)
                if self.acks_seq_number[metric_seq_num] != 1:
                    print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_Cpu.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmiting...")
                    self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_Cpu.task_type, 0, 0, 0, 0, round(cpu_usage))
                    max_retransmission_tries-=1
                else: 
                    max_retransmission_tries = -1
            
            if max_retransmission_tries == 0:
                print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_Cpu.task_type)} task.")



    def executeRAMTask(self, packet_Ram: NetTask.NetTaskTASKcpuramPacket):
        self.tasks_seq_number[packet_Ram.seq_num] = 1

        periodically_do = 3
        while (periodically_do > 0):
            periodically_do-=1
            time.sleep(packet_Ram.frequency)
            # Get RAM usage percentage
            ram_usage = psutil.virtual_memory().percent
            print(f"Current RAM Usage: {ram_usage}%")


            # Use lock to safely read and update current_seq_num
            with self.seq_num_lock:
                # Read and use current_seq_num in the max function
                seq_num_to_use = max(packet_Ram.seq_num, self.current_seq_num, self.last_task_seq_num)

                # Update current_seq_num and other variables
                metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_Ram.task_type, 0, 0, 0, 0, round(ram_usage))
                self.current_seq_num = metric_seq_num
                self.acks_seq_number[metric_seq_num] = 0

            if (packet_Ram.task_threshold < ram_usage):
                self.send_alert_message(metric_seq_num, packet_Ram.task_type, packet_Ram.task_threshold, round(ram_usage))

            max_retransmission_tries = 5
            while max_retransmission_tries > 0:
                time.sleep(4)
                if self.acks_seq_number[metric_seq_num] != 1:
                    print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_Ram.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmitting...")
                    self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_Ram.task_type, 0, 0, 0, 0, round(ram_usage))
                    max_retransmission_tries -= 1
                else:
                    max_retransmission_tries = -1  # Exit the loop if ACK received

            if max_retransmission_tries == 0:
                print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_Ram.task_type)} task.")
            

    def executeInterfaceTask(self, packet_interface: NetTask.NetTaskTASKinterfacePacket):
        self.tasks_seq_number[packet_interface.seq_num] = 1

        interface_name = "eth" + str(packet_interface.task_interface) 
        if utils.AgentUtils.is_interface_active(interface_name):
            print(f"Interface {interface_name} exists, analyzing packets per second...")

            periodically_do = 3
            while (periodically_do > 0):
                periodically_do-=1
                pps_result = utils.AgentUtils.get_packets_per_second(interface_name, packet_interface.frequency)
                print(f"{interface_name} current pps: {pps_result}pps")

                # Use lock to safely read and update current_seq_num
                with self.seq_num_lock:
                    # Read and use current_seq_num in the max function
                    seq_num_to_use = max(packet_interface.seq_num, self.current_seq_num, self.last_task_seq_num)

                    # Update current_seq_num and other variables
                    metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_interface.task_type, 0, 0, 0, 0, round(pps_result))
                    self.current_seq_num = metric_seq_num
                    self.acks_seq_number[metric_seq_num] = 0

                if (packet_interface.task_threshold < pps_result):
                    self.send_alert_message(metric_seq_num, packet_interface.task_type, packet_interface.task_threshold, round(pps_result))

                max_retransmission_tries = 5
                while (max_retransmission_tries > 0):
                    time.sleep(4)
                    if self.acks_seq_number[metric_seq_num] != 1:
                        print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_interface.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmiting...")
                        self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_interface.task_type, 0, 0, 0, 0, round(pps_result))
                        max_retransmission_tries-=1
                    else: 
                        max_retransmission_tries = -1
                
                if max_retransmission_tries == 0:
                    print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_interface.task_type)} task.")


    def executeLatencyTask(self, packet_latency: NetTask.NetTaskTASKlatencyPacket):
        self.tasks_seq_number[packet_latency.seq_num] = 1

        periodically_do = 3
        while (periodically_do > 0):
            periodically_do-=1

            dest_ip = utils.AgentUtils.ints_to_ip(packet_latency.task_destination_ip_1, packet_latency.task_destination_ip_2, packet_latency.task_destination_ip_3, packet_latency.task_destination_ip_4)
            print(f"ip para ping: {dest_ip}")
            avg_latency = utils.AgentUtils.measure_latency(packet_latency.task_packet_count, dest_ip) 

            # Use lock to safely read and update current_seq_num
            with self.seq_num_lock:
                # Read and use current_seq_num in the max function
                seq_num_to_use = max(packet_latency.seq_num, self.current_seq_num, self.last_task_seq_num)

                # Update current_seq_num and other variables
                metric_seq_num = self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_latency.task_type, packet_latency.task_destination_ip_1, packet_latency.task_destination_ip_2, packet_latency.task_destination_ip_3, packet_latency.task_destination_ip_4, round(avg_latency))
                self.current_seq_num = metric_seq_num
                self.acks_seq_number[metric_seq_num] = 0

            if (packet_latency.task_threshold < avg_latency):
                self.send_alert_message(metric_seq_num, packet_latency.task_type, packet_latency.task_threshold, round(avg_latency))

            max_retransmission_tries = 5
            while (max_retransmission_tries > 0):
                time.sleep(4)
                if self.acks_seq_number[metric_seq_num] != 1:
                    print(f"Timeout exceeded for {NetTask.NetTaskProtocol.taskType(packet_latency.task_type)} task of sequence number: {metric_seq_num}'s ACK, retransmiting...")
                    self.netTaskProtocol.sendMETRICS(seq_num_to_use, packet_latency.task_type, packet_latency.task_destination_ip_1, packet_latency.task_destination_ip_2, packet_latency.task_destination_ip_3, packet_latency.task_destination_ip_4, round(avg_latency))
                    max_retransmission_tries-=1
                else: 
                    max_retransmission_tries = -1
            
            if max_retransmission_tries == 0:
                print(f"Maximum retransmission tries were exceeded for {NetTask.NetTaskProtocol.taskType(packet_latency.task_type)} task.")
            time.sleep(packet_latency.task_frequency)



    def cleanup(self):
        print("Encerrando agente...")
        self.udp_socket.close()
        self.tcp_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Inicia o NMSAgent e conecta a um servidor NMS.")
    parser.add_argument("server_ip", type=str, help="O IP do servidor NMS")
    parser.add_argument("server_udp_port", type=int, help="Porta UDP do servidor NMS")
    parser.add_argument("server_tcp_port", type=int, help="Porta TCP do servidor NMS")
    args = parser.parse_args()

    agent = NMSAgent(server_ip=args.server_ip, udp_port=args.server_udp_port, tcp_port=args.server_tcp_port)
    agent.start()