import socket
import threading
import time
import NetTask
import TasksReaderJson
import utils
import AlertFlow
import ResultsDatabase

class NMSServer:
    def __init__(self, udp_port=6000, tcp_port=5001):
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        
        # Inicializar socket UDP
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind(('0.0.0.0', self.udp_port))
        
        # Inicializar socket TCP
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_socket.bind(('0.0.0.0', self.tcp_port))
        self.tcp_socket.listen(3) 

        self.registered_agents_ip = {}  # Dictionary to store registered (ID -> ip)
        self.registered_agents_list = []
        self.registered_agents_ID = {} # Dictionary to store registered (ip -> ID)
        self.jsonCreated_ID = {} # Dictionary to check whether an agent already has its json file to store the results created
        self.ack_recieved_seq_num = {}
        self.metrics_seq_num = {}
        self.current_seq_num_ip = {}

    def start(self):
        ResultsDatabase.DatabaseHandler.delete_directory()
        # Thread UDP server listening(NetTask)
        udp_thread = threading.Thread(target=self.udp_server_listener)
        udp_thread.daemon = True
        udp_thread.start()

        # Thread TCP server listening (AlertFlow)
        tcp_thread = threading.Thread(target=self.tcp_server_listener)
        tcp_thread.daemon = True
        tcp_thread.start()

        print(f"Server listening at UDP Port: {self.udp_port} and TCP Port: {self.tcp_port}")

        # Keep the main thread running
        try:
            while True:
                time.sleep(1)         

        except KeyboardInterrupt:
            self.cleanup()

    def tcp_server_listener(self):
        while True:
            conn, addr = self.tcp_socket.accept()
            print(f"TCP connection from {addr}")
            threading.Thread(target=self.handle_tcp_connection, args=(conn, addr)).start()

    def handle_tcp_connection(self, conn: socket.socket, addr):
        try:
            while True:
                data = conn.recv(1024)
                if not data:
                    break

                alertPacket = AlertFlow.AlertFlowPacket.from_bytes(data)
                alertPacket.print_packet(addr[0], addr[1])
                ResultsDatabase.DatabaseHandler.save_alert_to_json(self.registered_agents_ID[addr[0]], addr[0], alertPacket)

        finally:
            print(f"Closing TCP connection with {addr}")
            conn.close()
    
    def udp_server_listener(self):
        while True:
            data, addr = self.udp_socket.recvfrom(100) # Always udp_port 6000
            packet = NetTask.NetTaskGenericPacket.from_bytes(data) # Decode bytes -> Packet
        
            if packet.packet_type == 0: #Register Packet
                message = NetTask.NetTaskSYNPacket.from_bytes(data)
                message.print_packet(addr[0], addr[1])

                udp_thread = threading.Thread(target=self.handle_registration, args=(message, addr[0], addr[1])) # Unique thread for unique agent
                udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                udp_thread.start() 

            if packet.packet_type == 1: # ACK packet
                message = NetTask.NetTaskACKPacket.from_bytes(data)
                message.print_packet(addr[0], addr[1]) 

                self.ack_recieved_seq_num[message.seq_num, addr[0]] = 1
            
            if packet.packet_type == 3: # Metrics packet
                metricsPacket = NetTask.NetTaskMETRICSPacket.from_bytes(data)
    
                metricsPacket.print_packet(addr[0], addr[1])
                
                udp_thread = threading.Thread(target=self.handle_metrics, args=(metricsPacket, addr[0], addr[1])) 
                udp_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                udp_thread.start()

    def handle_metrics(self, metricsPacket: NetTask.NetTaskMETRICSPacket, agent_ip: str, agent_port: int,):
        if (metricsPacket.seq_num, agent_ip) in self.metrics_seq_num:
            print("^ DUPLICATE ^")

        netTaskProtocol = NetTask.NetTaskProtocol(self.udp_socket, agent_ip, agent_port, socket.gethostname())
        netTaskProtocol.sendACK(metricsPacket.seq_num)
        
        if (metricsPacket.seq_num, agent_ip) not in self.metrics_seq_num:
            self.metrics_seq_num[metricsPacket.seq_num, agent_ip] = 1
            self.current_seq_num_ip[agent_ip] = metricsPacket.seq_num

            if (self.registered_agents_ID[agent_ip], 1) not in self.jsonCreated_ID:
                self.jsonCreated_ID[self.registered_agents_ID[agent_ip]] = 1
                ResultsDatabase.DatabaseHandler.initialize_agent_file(self.registered_agents_ID[agent_ip], agent_ip)
            
            agent = "Unknown Agent"
            dest_ip = utils.AgentUtils.ints_to_ip(metricsPacket.task_server_ip_1, metricsPacket.task_server_ip_2, metricsPacket.task_server_ip_3, metricsPacket.task_server_ip_4)
            if dest_ip in self.registered_agents_ID:
                agent = self.registered_agents_ID[dest_ip]
            ResultsDatabase.DatabaseHandler.save_metric_to_json(self.registered_agents_ID[agent_ip], agent_ip, metricsPacket, agent, dest_ip)



    def handle_registration(self, message: 'NetTask.NetTaskSYNPacket', agent_ip: str, agent_port: int):
        if message.source_id in self.registered_agents_list:
            print("^ DUPLICATE ^")

        netTaskProtocol = NetTask.NetTaskProtocol(self.udp_socket, agent_ip, agent_port, socket.gethostname())
        netTaskProtocol.sendACK(message.seq_num)
        
        if message.source_id not in self.registered_agents_list:

            self.registered_agents_ip[message.source_id] = agent_ip
            self.registered_agents_ID[agent_ip] = message.source_id
            self.registered_agents_list.append(message.source_id)

            print(f"Registered agent: {message.source_id} with IP: {agent_ip}")

            self.current_seq_num_ip[agent_ip] = message.seq_num

            tasks = TasksReaderJson.JsonReader.load()

            for task in tasks["tasks"]:
                task_id = task["task_id"]
               
                print(f"--------\nReady to send tasks for {message.source_id}")

                device_instructions = TasksReaderJson.JsonReader.get_device_instructions_by_id(task, message.source_id)
                if device_instructions != None: # This isn't for this agent

                    if device_instructions["device_metrics"]["cpu_usage"] == True: # CPU task 
                        sent_seq_num = netTaskProtocol.sendTASKcpuram(self.current_seq_num_ip[agent_ip], task["frequency"], 0, device_instructions["alertflow_conditions"]["cpu_usage"])
                        self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
                        retransmission_seq_num = self.current_seq_num_ip[agent_ip]
                        self.current_seq_num_ip[agent_ip] = sent_seq_num
                        
                        cpu_retransmission_thread = threading.Thread(target=self.CPU_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, device_instructions, netTaskProtocol)) 
                        cpu_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                        cpu_retransmission_thread.start() 

                        
                    
                    if device_instructions["device_metrics"]["ram_usage"] == True: #RAM task
                        sent_seq_num = netTaskProtocol.sendTASKcpuram(self.current_seq_num_ip[agent_ip], task["frequency"], 1, device_instructions["alertflow_conditions"]["ram_usage"])
                        self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
                        retransmission_seq_num = self.current_seq_num_ip[agent_ip]
                        self.current_seq_num_ip[agent_ip] = sent_seq_num
                        
                        ram_retransmission_thread = threading.Thread(target=self.RAM_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, device_instructions, netTaskProtocol)) 
                        ram_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                        ram_retransmission_thread.start() 

                    interfaces_to_check = TasksReaderJson.JsonReader.get_device_interface_stats(task, message.source_id)
                    if interfaces_to_check != None:
                        for ethNUM in interfaces_to_check: #INTERFACES tasks
                            pps_threshold = TasksReaderJson.JsonReader.get_alertflow(task, message.source_id)
                            sent_seq_num = netTaskProtocol.sendTASKinterface(self.current_seq_num_ip[agent_ip], task["frequency"], pps_threshold["interface_stats"], ethNUM)
                            self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
                            retransmission_seq_num = self.current_seq_num_ip[agent_ip]
                            self.current_seq_num_ip[agent_ip] = sent_seq_num
                            
                            ram_retransmission_thread = threading.Thread(target=self.INTERFACES_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, pps_threshold, netTaskProtocol, ethNUM)) 
                            ram_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                            ram_retransmission_thread.start() 
                    
                    # Latency tasks
                    latency = TasksReaderJson.JsonReader.get_latency_object(task, message.source_id)
                    latency_threshold = TasksReaderJson.JsonReader.get_alertflow(task, message.source_id)
                    a, b, c, d = utils.AgentUtils.ip_to_ints(latency["destination"])

                    sent_seq_num = netTaskProtocol.sendTASKlatency(self.current_seq_num_ip[agent_ip], task["frequency"], latency_threshold["latency"], latency["packet_count"], latency["frequency"], a, b, c, d)
                    self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
                    retransmission_seq_num = self.current_seq_num_ip[agent_ip]
                    self.current_seq_num_ip[agent_ip] = sent_seq_num

                    latency_retransmission_thread = threading.Thread(target=self.LATENCY_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, latency_threshold, latency, a, b, c, d, netTaskProtocol)) 
                    latency_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    latency_retransmission_thread.start()

                    
                    # Packet Loss tasks
                    packet_loss_thread = threading.Thread(target=self.PACKET_LOSS_task, args=(task, message, netTaskProtocol, agent_ip, task_id)) 
                    packet_loss_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    packet_loss_thread.start()

                    # Jitter tasks
                    jitter_thread = threading.Thread(target=self.JITTER_task, args=(task, message, netTaskProtocol, agent_ip, task_id)) 
                    jitter_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    jitter_thread.start()

                    # Throughtput/bandwidth tasks
                    throughput_thread = threading.Thread(target=self.THROUGHPUT_task, args=(task, message, netTaskProtocol, agent_ip, task_id)) 
                    throughput_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
                    throughput_thread.start()
                     
                    
            print(f"All tasks sent for {message.source_id}")


    def PACKET_LOSS_task(self, task: object, message: 'NetTask.NetTaskSYNPacket', netTaskProtocol: NetTask.NetTaskProtocol, agent_ip: str, task_id: str):
        packet_loss = TasksReaderJson.JsonReader.get_packet_loss_object(task, message.source_id)
        while (packet_loss["server_address"] not in self.registered_agents_ip.values()):
            print(f"Waiting for all the necessary agents to be registered to send {task_id} packet loss task...")
            time.sleep(5)
        print(f"--------\nReady to send packet loss task for {message.source_id}")
        
        packet_loss_threshold = TasksReaderJson.JsonReader.get_alertflow(task, message.source_id)
        a, b, c, d = utils.AgentUtils.ip_to_ints(packet_loss["server_address"])

        sent_seq_num = netTaskProtocol.sendTASKjitterpacketloss(self.current_seq_num_ip[agent_ip], task["frequency"], 6, packet_loss_threshold["packet_loss"], packet_loss["mode"], packet_loss["duration"], packet_loss["frequency"], a, b, c, d)
        self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
        retransmission_seq_num = self.current_seq_num_ip[agent_ip]
        self.current_seq_num_ip[agent_ip] = sent_seq_num

        ram_retransmission_thread = threading.Thread(target=self.PACKET_LOSS_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, packet_loss_threshold, packet_loss, a, b, c, d, netTaskProtocol)) 
        ram_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
        ram_retransmission_thread.start()  

    
    def JITTER_task(self, task: object, message: 'NetTask.NetTaskSYNPacket', netTaskProtocol: NetTask.NetTaskProtocol, agent_ip: str, task_id: str):
        jitter = TasksReaderJson.JsonReader.get_jitter_object(task, message.source_id)
        while (jitter["server_address"] not in self.registered_agents_ip.values()):
            print(f"Waiting for all the necessary agents to be registered to send {task_id} jitter task...")
            time.sleep(5)
        print(f"--------\nReady to send jitter task for {message.source_id}")

        jitter = TasksReaderJson.JsonReader.get_jitter_object(task, message.source_id)
        jitter_threshold = TasksReaderJson.JsonReader.get_alertflow(task, message.source_id)
        a, b, c, d = utils.AgentUtils.ip_to_ints(jitter["server_address"])

        sent_seq_num = netTaskProtocol.sendTASKjitterpacketloss(self.current_seq_num_ip[agent_ip], task["frequency"], 5, jitter_threshold["jitter"], jitter["mode"], jitter["duration"], jitter["frequency"], a, b, c, d)

        self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
        retransmission_seq_num = self.current_seq_num_ip[agent_ip]
        self.current_seq_num_ip[agent_ip] = sent_seq_num

        ram_retransmission_thread = threading.Thread(target=self.JITTER_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, jitter_threshold, jitter, a, b, c, d, netTaskProtocol)) 
        ram_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
        ram_retransmission_thread.start() 


    def THROUGHPUT_task(self, task: object, message: 'NetTask.NetTaskSYNPacket', netTaskProtocol: NetTask.NetTaskProtocol, agent_ip: str, task_id: str):
        throughput = TasksReaderJson.JsonReader.get_throughput_object(task, message.source_id)
        while (throughput["server_address"] not in self.registered_agents_ip.values()):
            print(f"Waiting for all the necessary agents to be registered to send {task_id} jitter task...")
            time.sleep(5)
        print(f"--------\nReady to send jitter task for {message.source_id}")

        throughput_threshold = TasksReaderJson.JsonReader.get_alertflow(task, message.source_id)
        a, b, c, d = utils.AgentUtils.ip_to_ints(throughput["server_address"])

        sent_seq_num = netTaskProtocol.sendTASKthroughput(self.current_seq_num_ip[agent_ip], task["frequency"], 2, throughput_threshold["packet_loss"], throughput["mode"], throughput["duration"], throughput["transport_type"], throughput["frequency"], a, b, c, d)

        self.ack_recieved_seq_num[sent_seq_num, agent_ip] = 0
        retransmission_seq_num = self.current_seq_num_ip[agent_ip]
        self.current_seq_num_ip[agent_ip] = sent_seq_num

        
        throughput_retransmission_thread = threading.Thread(target=self.THROUGHPUT_task_retransmission, args=(sent_seq_num, agent_ip, retransmission_seq_num, task, throughput_threshold, throughput, a, b, c, d, netTaskProtocol)) 
        throughput_retransmission_thread.daemon = True # This thread will wait for all inside threads to be finished before finishing itself
        throughput_retransmission_thread.start() 


    def CPU_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task: object, device_instructions: object, netTaskProtocol: NetTask.NetTaskProtocol):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s CPU task ACK, retransmiting...")
                netTaskProtocol.sendTASKcpuram(retransmission_seq_num, task["frequency"], 0, device_instructions["alertflow_conditions"]["cpu_usage"])
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for CPU task of {task_id}.")
    


    def RAM_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task: object, device_instructions: object, netTaskProtocol: NetTask.NetTaskProtocol):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s RAM task ACK, retransmiting...")
                netTaskProtocol.sendTASKcpuram(retransmission_seq_num, task["frequency"], 1, device_instructions["alertflow_conditions"]["ram_usage"])
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for RAM task of {task_id}.")
    
    def INTERFACES_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task: object, pps_threshold: int, netTaskProtocol: NetTask.NetTaskProtocol, ethNUM: int):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s INTERFACES task ACK, retransmiting...")
                netTaskProtocol.sendTASKinterface(retransmission_seq_num, task["frequency"], pps_threshold["interface_stats"], ethNUM)
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for INTERFACES task of {task_id}.")
        
    def LATENCY_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task, latency_threshold, latency, a: int, b: int, c: int, d: int, netTaskProtocol: NetTask.NetTaskProtocol): 
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s LATENCY task ACK, retransmiting...")
                netTaskProtocol.sendTASKlatency(retransmission_seq_num, task["frequency"], latency_threshold["latency"], latency["packet_count"], latency["frequency"], a, b, c, d)
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for LATENCY task of {task_id}.")

    def PACKET_LOSS_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task, packet_loss_threshold: int, packet_loss, a: int, b, c, d, netTaskProtocol: NetTask.NetTaskProtocol):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s PACKET LOSS task ACK, retransmiting...")
                netTaskProtocol.sendTASKjitterpacketloss(retransmission_seq_num, task["frequency"], 6, packet_loss_threshold["packet_loss"], packet_loss["mode"], packet_loss["duration"], packet_loss["frequency"], a, b, c, d)
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for PACKET LOSS task of {task_id}.")
    
    def JITTER_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task, jitter_threshold: int, jitter, a: int, b, c, d, netTaskProtocol: NetTask.NetTaskProtocol):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s JITTER task ACK, retransmiting...")
                netTaskProtocol.sendTASKjitterpacketloss(retransmission_seq_num, task["frequency"], 5, jitter_threshold["jitter"], jitter["mode"], jitter["duration"], jitter["frequency"], a, b, c, d)
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for PACKET LOSS task of {task_id}.")

    def THROUGHPUT_task_retransmission(self, sent_seq_num: int, agent_ip: str, retransmission_seq_num: int, task, throughput_threshold: int, throughput, a: int, b, c, d, netTaskProtocol: NetTask.NetTaskProtocol):
        task_id = task["task_id"]

        max_retransmission_tries = 5
        while (max_retransmission_tries > 0):
            time.sleep(6)
            if self.ack_recieved_seq_num[sent_seq_num, agent_ip] != 1:
                print(f"Timeout exceeded for {task_id}'s THROUGHPUT task ACK, retransmiting...")
                netTaskProtocol.sendTASKthroughput(retransmission_seq_num, task["frequency"], 2, throughput_threshold["packet_loss"], throughput["mode"], throughput["duration"], throughput["transport_type"], throughput["frequency"], a, b, c, d)
                max_retransmission_tries-=1
            else: 
                max_retransmission_tries = -1
        
        if max_retransmission_tries == 0:
            print(f"Maximum retransmission tries were exceeded for THROUGHPUT task of {task_id}.")

    def cleanup(self):
        print("Shutting down server ...")
        self.udp_socket.close()
        self.tcp_socket.close()
        
if __name__ == "__main__":
    server = NMSServer()
    server.start()
