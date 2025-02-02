import socket
import struct
import utils

class NetTaskMETRICSPacket:
    def __init__(self, packet_type: int, seq_num: int, task_type: int, task_server_ip_1: int, task_server_ip_2: int, task_server_ip_3: int, task_server_ip_4: int, metric_value: int):
        # Validate inputs
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        
        self.packet_type = packet_type
        self.seq_num = seq_num
        self.task_type = task_type
        self.task_server_ip_1 = task_server_ip_1 
        self.task_server_ip_2 = task_server_ip_2 
        self.task_server_ip_3 = task_server_ip_3 
        self.task_server_ip_4 = task_server_ip_4 
        self.metric_value = metric_value
        
    def to_bytes(self) -> bytes:
        self.seq_num += 1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!B", self.task_type)
        if (not (self.task_server_ip_1 == 0 and self.task_server_ip_2 == 0 and self.task_server_ip_3 == 0 and self.task_server_ip_4 == 0)):
            packet += struct.pack("!B", self.task_server_ip_1)
            packet += struct.pack("!B", self.task_server_ip_2)
            packet += struct.pack("!B", self.task_server_ip_3)
            packet += struct.pack("!B", self.task_server_ip_4)
        # Encode metric_value
        if self.metric_value <= 255:  # Fits in 1 bytes
            packet += struct.pack("!B", self.metric_value)
        elif self.metric_value <= 65535:  # Fits in 2 bytes
            packet += struct.pack("!H", self.metric_value)
        else:  # Requires 3 bytes
            packet += struct.pack("!I", self.metric_value)[1:]  # Take the last 3 bytes

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 4:  # Minimum required length for packet_type, seq_num, task_type, and metric_value
            raise ValueError("Insufficient data to decode NetTaskMETRICSPacket")
        # Decode fields in the same order as `to_bytes`
        offset = 0
        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1
        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1
        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1
        
        remaining_length = len(data) - offset
        if remaining_length >= 5:
            task_server_ip_1 = struct.unpack("!B", data[offset:offset + 1])[0]
            offset += 1
            task_server_ip_2 = struct.unpack("!B", data[offset:offset + 1])[0]
            offset += 1
            task_server_ip_3 = struct.unpack("!B", data[offset:offset + 1])[0]
            offset += 1
            task_server_ip_4 = struct.unpack("!B", data[offset:offset + 1])[0]
            offset += 1

            # Decode metric_value
            remaining_length = len(data) - offset
            if remaining_length == 1:  # 1-byte metric_value
                metric_value = struct.unpack("!B", data[offset:offset + 1])[0]
                offset += 1
            elif remaining_length == 2:  # 2-byte metric_value
                metric_value = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += 2
            elif remaining_length == 3:  # 3-byte metric_value
                metric_value = struct.unpack("!I", b'\x00' + data[offset:offset + 3])[0]
                offset += 3
            else:
                raise ValueError("Invalid metric_value length in data")
            # Return a new instance of NetTaskMETRICSPacket
            return cls(packet_type, seq_num, task_type, task_server_ip_1, task_server_ip_2, task_server_ip_3, task_server_ip_4, metric_value)
        else:
            # Decode metric_value
            remaining_length = len(data) - offset
            if remaining_length == 1:  # 1-byte metric_value
                metric_value = struct.unpack("!B", data[offset:offset + 1])[0]
                offset += 1
            elif remaining_length == 2:  # 2-byte metric_value
                metric_value = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += 2
            elif remaining_length == 3:  # 3-byte metric_value
                metric_value = struct.unpack("!I", b'\x00' + data[offset:offset + 3])[0]
                offset += 3
            else:
                raise ValueError("Invalid metric_value length in data")
            # Return a new instance of NetTaskMETRICSPacket
            return cls(packet_type, seq_num, task_type, 0, 0, 0, 0, metric_value) 


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type: {self.packet_type} wich is {NetTaskProtocol.packetType(self.packet_type)}")
        print(f"Sequence number: {self.seq_num}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        if (not (self.task_server_ip_1 == 0 and self.task_server_ip_2 == 0 and self.task_server_ip_3 == 0 and self.task_server_ip_4 == 0)):
            if (self.task_type == 5):
                print(f"Destination ip: {utils.AgentUtils.ints_to_ip(self.task_server_ip_1, self.task_server_ip_2, self.task_server_ip_3, self.task_server_ip_4)}")
            else:
                print(f"Server ip: {utils.AgentUtils.ints_to_ip(self.task_server_ip_1, self.task_server_ip_2, self.task_server_ip_3, self.task_server_ip_4)}")
        if (self.task_type == 0 or self.task_type == 1 or self.task_type == 6):
            print(f"Metric value: {self.metric_value}%")
        elif (self.task_type == 4):
            print(f"Metric value: {self.metric_value} pps")
        elif (self.task_type == 3 or self.task_type == 5):
            print(f"Metric value: {self.metric_value} ms")
        elif (self.task_type == 2):
            print(f"Metric value: {self.metric_value} Kbits/sec")
        

        else: print(f"Metric value: {self.metric_value}")
        print("-------------------")

class NetTaskGenericPacket:
    def __init__(self, packet_type: int, seq_num: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")

        self.packet_type = packet_type
        self.seq_num = seq_num

    @classmethod
    def from_bytes(cls, data: bytes):
        # Parse packet_type and seq_num
        first_byte = struct.unpack("!B", data[0:1])[0]

        if first_byte < 8:  # Indicates 2-byte encoding (separate packet_type and seq_num)
            packet_type = first_byte  # First byte is the packet_type
            seq_num = struct.unpack("!B", data[1:2])[0]  # Second byte is the seq_num
        else:  # Indicates 1-byte compact encoding
            header = first_byte
            packet_type = (header >> 5) & 0x07  # Extract the 3-bit packet_type
            seq_num = header & 0x1F  # Extract the 5-bit seq_num

        # Return a NetTaskGenericPacket instance
        return cls(packet_type, seq_num)


class NetTaskGenericTASKPacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 5:  # Minimum required length for packet_type, seq_num, frequency, and task_type
            raise ValueError("Insufficient data to decode NetTaskGenericTASKPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        # Return a new instance of NetTaskGenericTASKPacket
        return cls(packet_type, seq_num, frequency, task_type)


class NetTaskTASKcpuramPacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int, task_threshold: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        if task_threshold >= 65536:
            raise ValueError("task_threshold must be less than 65536 (fits in 16 bits)")

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type
        self.task_threshold = task_threshold 

    def to_bytes(self) -> bytes:
        self.seq_num +=1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!H", self.frequency)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 7:  # Minimum required length
            raise ValueError("Insufficient data to decode NetTaskTASKcpuramPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        # Return a new instance of NetTaskTASKcpuramPacket
        return cls(packet_type, seq_num, frequency, task_type, task_threshold)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}")
        print(f"Frequency: {self.frequency}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        print(f"Task threshold: {self.task_threshold}%")
        print("-------------------")

class NetTaskTASKbandwidthPacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_mode: int, task_duration: int, task_transport_type: int, task_frequency: int, task_server_ip_1: int, task_server_ip_2: int, task_server_ip_3: int, task_server_ip_4: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        if task_threshold >= 65536:
            raise ValueError("task_threshold must be less than 65536 (fits in 16 bits)")
        if task_mode >= 3:
            raise ValueError("packet_type must be less than 3 (fits in 1 bit)")
        if task_duration >= 256:
            raise ValueError("task_duration must be less than 256 (fits in 8 bits)")
        if task_frequency >= 65536: 
            raise ValueError("task_frequency must be less than 65536 (fits in 16 bits)")
        if task_server_ip_1 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_2 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_3 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_4 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")        

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type
        self.task_threshold = task_threshold
        self.task_mode = task_mode
        self.task_duration = task_duration
        self.task_transport_type = task_transport_type
        self.task_frequency = task_frequency
        self.task_server_ip_1 = task_server_ip_1 
        self.task_server_ip_2 = task_server_ip_2 
        self.task_server_ip_3 = task_server_ip_3 
        self.task_server_ip_4 = task_server_ip_4 

    def to_bytes(self) -> bytes:
        self.seq_num +=1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!H", self.frequency)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)
        packet += struct.pack("!B", self.task_mode)
        packet += struct.pack("!B", self.task_duration)
        packet += struct.pack("!B", self.task_transport_type)                        
        packet += struct.pack("!H", self.task_frequency)
        packet += struct.pack("!B", self.task_server_ip_1)
        packet += struct.pack("!B", self.task_server_ip_2)
        packet += struct.pack("!B", self.task_server_ip_3)
        packet += struct.pack("!B", self.task_server_ip_4)

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 14:  # Minimum required length for all fields
            raise ValueError("Insufficient data to decode NetTaskTASKbandwidthPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_mode = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_duration = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_transport_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_server_ip_1 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_2 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_3 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_4 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        # Return a new instance of NetTaskTASKjitterpacketlossPacket
        return cls(packet_type, seq_num, frequency, task_type, task_threshold, task_mode, task_duration, task_transport_type, task_frequency, task_server_ip_1, task_server_ip_2, task_server_ip_3, task_server_ip_4)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}")
        print(f"Frequency: {self.frequency}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        if self.task_type == 5: #Jitter
            print(f"Task threshold: {self.task_threshold} ms")
        else: #Packet Loss
            print(f"Task threshold: {self.task_threshold}%")
        print(f"Task tool: Iperf")
        if self.task_mode == 0:
            print(f"Task mode: Client")
        else:
            print(f"Task mode: Server")
        print(f"Task duration: {self.task_duration} sec")
        print(f"Task frequency: {self.task_frequency}")
        print(f"Task destination ip: {utils.AgentUtils.ints_to_ip(self.task_server_ip_1, self.task_server_ip_2, self.task_server_ip_3, self.task_server_ip_4)}")
        print("-------------------")


class NetTaskTASKjitterpacketlossPacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_mode: int, task_duration: int, task_frequency: int, task_server_ip_1: int, task_server_ip_2: int, task_server_ip_3: int, task_server_ip_4: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        if task_threshold >= 65536:
            raise ValueError("task_threshold must be less than 65536 (fits in 16 bits)")
        if task_mode >= 3:
            raise ValueError("packet_type must be less than 3 (fits in 1 bit)")
        if task_duration >= 256:
            raise ValueError("task_duration must be less than 256 (fits in 8 bits)")
        if task_frequency >= 65536: 
            raise ValueError("task_frequency must be less than 65536 (fits in 16 bits)")
        if task_server_ip_1 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_2 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_3 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")
        if task_server_ip_4 >= 256:
            raise ValueError("task_server_ip_1 must be less than 256 (fits in 8 bits)")        

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type
        self.task_threshold = task_threshold
        self.task_mode = task_mode
        self.task_duration = task_duration
        self.task_frequency = task_frequency
        self.task_server_ip_1 = task_server_ip_1 
        self.task_server_ip_2 = task_server_ip_2 
        self.task_server_ip_3 = task_server_ip_3 
        self.task_server_ip_4 = task_server_ip_4 

    def to_bytes(self) -> bytes:
        self.seq_num +=1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!H", self.frequency)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)
        packet += struct.pack("!B", self.task_mode)
        packet += struct.pack("!B", self.task_duration)
        packet += struct.pack("!H", self.task_frequency)
        packet += struct.pack("!B", self.task_server_ip_1)
        packet += struct.pack("!B", self.task_server_ip_2)
        packet += struct.pack("!B", self.task_server_ip_3)
        packet += struct.pack("!B", self.task_server_ip_4)

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 14:  # Minimum required length for all fields
            raise ValueError("Insufficient data to decode NetTaskTASKjitterpacketlossPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_mode = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_duration = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_server_ip_1 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_2 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_3 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_server_ip_4 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        # Return a new instance of NetTaskTASKjitterpacketlossPacket
        return cls(packet_type, seq_num, frequency, task_type, task_threshold, task_mode, task_duration, task_frequency, task_server_ip_1, task_server_ip_2, task_server_ip_3, task_server_ip_4)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}")
        print(f"Frequency: {self.frequency}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        if self.task_type == 5: #Jitter
            print(f"Task threshold: {self.task_threshold} ms")
        else: #Packet Loss
            print(f"Task threshold: {self.task_threshold}%")
        print(f"Task tool: Iperf")
        if self.task_mode == 0:
            print(f"Task mode: Client")
        else:
            print(f"Task mode: Server")
        print(f"Task duration: {self.task_duration} sec")
        print(f"Task frequency: {self.task_frequency}")
        print(f"Task destination ip: {utils.AgentUtils.ints_to_ip(self.task_server_ip_1, self.task_server_ip_2, self.task_server_ip_3, self.task_server_ip_4)}")
        print("-------------------")


class NetTaskTASKlatencyPacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_packet_count: int, task_frequency: int, task_destination_ip_1: int, task_destination_ip_2: int, task_destination_ip_3: int, task_destination_ip_4: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        if task_threshold >= 65536:
            raise ValueError("task_threshold must be less than 65536 (fits in 16 bits)")
        if task_packet_count >= 256:
            raise ValueError("task_packet_count must be less than 256 (fits in 8 bits)")
        if task_frequency >= 65536: 
            raise ValueError("task_frequency must be less than 65536 (fits in 16 bits)")
        if task_destination_ip_1 >= 256:
            raise ValueError("task_destination_ip_1 must be less than 256 (fits in 8 bits)")
        if task_destination_ip_2 >= 256:
            raise ValueError("task_destination_ip_1 must be less than 256 (fits in 8 bits)")
        if task_destination_ip_3 >= 256:
            raise ValueError("task_destination_ip_1 must be less than 256 (fits in 8 bits)")
        if task_destination_ip_4 >= 256:
            raise ValueError("task_destination_ip_1 must be less than 256 (fits in 8 bits)")        

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type
        self.task_threshold = task_threshold
        self.task_packet_count = task_packet_count
        self.task_frequency = task_frequency
        self.task_destination_ip_1 = task_destination_ip_1 
        self.task_destination_ip_2 = task_destination_ip_2 
        self.task_destination_ip_3 = task_destination_ip_3 
        self.task_destination_ip_4 = task_destination_ip_4 

    def to_bytes(self) -> bytes:
        self.seq_num +=1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!H", self.frequency)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)
        packet += struct.pack("!B", self.task_packet_count)
        packet += struct.pack("!H", self.task_frequency)
        packet += struct.pack("!B", self.task_destination_ip_1)
        packet += struct.pack("!B", self.task_destination_ip_2)
        packet += struct.pack("!B", self.task_destination_ip_3)
        packet += struct.pack("!B", self.task_destination_ip_4)

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 12:  # Minimum required length for all fields
            raise ValueError("Insufficient data to decode NetTaskTASKlatencyPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_packet_count = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_destination_ip_1 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_destination_ip_2 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_destination_ip_3 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_destination_ip_4 = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        # Return a new instance of NetTaskTASKlatencyPacket
        return cls(packet_type, seq_num, frequency, task_type, task_threshold, task_packet_count, task_frequency, task_destination_ip_1, task_destination_ip_2, task_destination_ip_3, task_destination_ip_4)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}")
        print(f"Frequency: {self.frequency}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        print(f"Task threshold: {self.task_threshold} ms")
        print(f"Task tool: Ping")
        print(f"Task packet count: {self.task_packet_count}")
        print(f"Task frequency: {self.task_frequency}")
        print(f"Task destination ip: {utils.AgentUtils.ints_to_ip(self.task_destination_ip_1, self.task_destination_ip_2, self.task_destination_ip_3, self.task_destination_ip_4)}")
        print("-------------------")

class NetTaskTASKinterfacePacket:
    def __init__(self, packet_type: int, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_interface: int):
        # Validate the values
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if frequency >= 65536: 
            raise ValueError("frequency must be less than 65536 (fits in 16 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        if task_threshold >= 65536:
            raise ValueError("task_threshold must be less than 65536 (fits in 16 bits)")
        if task_interface >= 4:
            raise ValueError("task_interface must be less than 4 (fits in 2 bits)")

        self.packet_type = packet_type
        self.seq_num = seq_num
        self.frequency = frequency
        self.task_type = task_type
        self.task_threshold = task_threshold
        self.task_interface = task_interface


    def to_bytes(self) -> bytes:
        self.seq_num +=1
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        packet += struct.pack("!H", self.frequency)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)
        packet += struct.pack("!B", self.task_interface)

        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 8:
            raise ValueError("Insufficient data to decode NetTaskTASKinterfacePacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        packet_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        frequency = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        task_interface = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        # Return a new instance of NetTaskTASKinterfacePacket
        return cls(packet_type, seq_num, frequency, task_type, task_threshold, task_interface)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet received from IP {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}")
        print(f"Frequency: {self.frequency}")
        print(f"Task type: {self.task_type} which is {NetTaskProtocol.taskType(self.task_type)}")
        print(f"Task threshold: {self.task_threshold} pps")
        print(f"Task Interface: eth{self.task_interface}")
        print("-------------------")

class NetTaskACKPacket:
    def __init__(self, packet_type: int, seq_num: int):
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        
        self.packet_type = packet_type
        self.seq_num = seq_num

    def to_bytes(self) -> bytes:
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        
        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Decode packet_type and seq_num as separate bytes
        packet_type = struct.unpack("!B", data[0:1])[0]  # First byte is packet_type
        seq_num = struct.unpack("!B", data[1:2])[0]      # Second byte is seq_num

        # Return a new instance of NetTaskACKPacket
        return cls(packet_type, seq_num)

    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet recieved from ip {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Sequence number: {self.seq_num}\n-------------------")

class NetTaskSYNPacket:
    def __init__(self, packet_type: int, seq_num: int, source_id: str):
        if packet_type >= 8:
            raise ValueError("packet_type must be less than 8 (fits in 3 bits)")
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        
        self.packet_type = packet_type
        self.seq_num = seq_num
        self.source_id = source_id

    def to_bytes(self) -> bytes:
        packet = struct.pack("!B", self.packet_type)
        packet += struct.pack("!B", self.seq_num)
        return packet + self.source_id.encode('utf-8')

    @classmethod
    def from_bytes(cls, data: bytes):
        # Decode packet_type and seq_num
        packet_type = struct.unpack("!B", data[0:1])[0]  # First byte is packet_type
        seq_num = struct.unpack("!B", data[1:2])[0]  # Second byte is seq_num

        # Decode the source_id
        source_id = data[2:].decode('utf-8')  # Remaining bytes are source_id

        # Return a new instance of NetTaskSYNPacket
        return cls(packet_type, seq_num, source_id)



    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet recieved from ip {source_ip} and port {source_port}")
        print(f"Packet type {self.packet_type} which is [{NetTaskProtocol.packetType(self.packet_type)}]")
        print(f"Agent_id: {self.source_id}")
        print(f"Sequence number: {self.seq_num}\n-------------------")

class NetTaskProtocol:
    def __init__(self, udp_socket: socket.socket, destination_ip: str, destination_port: int, source_id: str):
        self.netTaskSocket = udp_socket
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.source_id = source_id
   

    @staticmethod
    def packetType(packet_type: int) -> str:
        packets_type = {0 : 'SYN', 1 : 'ACK', 2 : 'TASK', 3 : 'METRICS'}
        if packet_type < 5 :
            if packets_type[packet_type] == 'SYN':
                return 'SYN'
            elif packets_type[packet_type] == 'ACK':
                return 'ACK'
            elif packets_type[packet_type] == 'TASK':
                return 'TASK'
            elif packets_type[packet_type] == 'METRICS':
                return 'METRICS'
        else: 
            return 'packet_type out of bounds'
        
    @staticmethod
    def taskType(task_type: int) -> str:
        tasks_type = {0 : 'CPU', 1 : 'RAM', 2 : 'THROUGHPUT', 3 : 'LATENCY', 4 : 'INTERFACES', 5 : 'JITTER', 6 : 'PACKET LOSS'}
        if task_type < 7:
            if tasks_type[task_type] == 'CPU':
                return 'CPU'
            elif tasks_type[task_type] == 'RAM':
                return 'RAM'
            elif tasks_type[task_type] == 'THROUGHPUT':
                return 'THROUGHPUT'
            elif tasks_type[task_type] == 'LATENCY':
                return 'LATENCY'
            elif tasks_type[task_type] == 'INTERFACES':
                return 'INTERFACES'
            elif tasks_type[task_type] == 'JITTER':
                return 'JITTER'
            elif tasks_type[task_type] == 'PACKET LOSS':
                return 'PACKET LOSS'
        else: 
            return 'task_type out of bounds'
        
    def registerSYN(self):
        packet = NetTaskSYNPacket(0, 0, self.source_id)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))
        print(f"------\nSent SYN to ip: {self.destination_ip} port: {self.destination_port}\n------")

        return packet.seq_num


    @staticmethod
    def isRegisterSYN(packet_type: int):
        if packet_type == 0:
            return True
        return False


    def sendACK(self, seq_num: int):
        packet = NetTaskACKPacket(1, seq_num)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))
        print(f"------\nSent ACK to ip: {self.destination_ip} port: {self.destination_port}\n------")
    
    @staticmethod
    def isACK(packet_type: int):
        if packet_type == 1:
            return True
        return False
    
    def sendTASKcpuram(self, seq_num: int, frequency: int, task_type: int, task_threshold: int) -> int:
        packet = NetTaskTASKcpuramPacket(2, seq_num, frequency, task_type, task_threshold)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))
       
        if (task_type == 0):
            print(f"Sent TASK CPU to ip: {self.destination_ip} port: {self.destination_port}\n------")
        else:
            print(f"Sent TASK RAM to ip: {self.destination_ip} port: {self.destination_port}\n------")
        
        return packet.seq_num
    
    def sendTASKinterface(self, seq_num: int, frequency: int, task_threshold: int, task_interface: int) -> int:
        packet = NetTaskTASKinterfacePacket(2, seq_num, frequency, 4, task_threshold, task_interface)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))

        print(f"Sent TASK INTERFACES to ip: {self.destination_ip} port: {self.destination_port}\n------")
        
        return packet.seq_num
    
    def sendTASKlatency(self, seq_num: int, frequency: int, task_threshold: int, task_packet_count: int, task_frequency: int, task_destination_ip_1: int, task_destination_ip_2: int, task_destination_ip_3: int, task_destination_ip_4: int) -> int:
        packet = NetTaskTASKlatencyPacket(2, seq_num, frequency, 3, task_threshold, task_packet_count, task_frequency, task_destination_ip_1, task_destination_ip_2, task_destination_ip_3, task_destination_ip_4)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))

        print(f"Sent TASK Latency to ip: {self.destination_ip} port: {self.destination_port}\n------")
        
        return packet.seq_num
    
    def sendTASKjitterpacketloss(self, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_mode: int, task_duration: int, task_frequency: int, task_server_ip_1: int, task_server_ip_2: int, task_server_ip_3: int, task_server_ip_4: int) -> int:
        packet = NetTaskTASKjitterpacketlossPacket(2, seq_num, frequency, task_type, task_threshold, task_mode, task_duration, task_frequency, task_server_ip_1, task_server_ip_2, task_server_ip_3, task_server_ip_4)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))

        if (task_type == 5):
            print(f"Sent TASK Jitter to ip: {self.destination_ip} port: {self.destination_port}\n------")
        else:
            print(f"Sent TASK Packet Loss to ip: {self.destination_ip} port: {self.destination_port}\n------")

        return packet.seq_num
    
    def sendTASKthroughput(self, seq_num: int, frequency: int, task_type: int, task_threshold: int, task_mode: int, task_duration: int, task_transport_type: int, task_frequency: int, task_server_ip_1: int, task_server_ip_2: int, task_server_ip_3: int, task_server_ip_4: int) -> int:
        packet = NetTaskTASKbandwidthPacket(2, seq_num, frequency, task_type, task_threshold, task_mode, task_duration, task_transport_type, task_frequency, task_server_ip_1, task_server_ip_2, task_server_ip_3, task_server_ip_4)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))

        print(f"Sent TASK Throughput to ip: {self.destination_ip} port: {self.destination_port}\n------")

        return packet.seq_num
    
    @staticmethod
    def isTASK(packet_type: int):
        if packet_type == 2:
            return True
        return False
    
    def sendMETRICS(self, seq_num: int, task_type: int, task_destination_ip_1: int, task_destination_ip_2: int, task_destination_ip_3: int, task_destination_ip_4: int, metric_value: int) -> int:
        packet = NetTaskMETRICSPacket(3, seq_num, task_type, task_destination_ip_1, task_destination_ip_2, task_destination_ip_3, task_destination_ip_4, metric_value)
        self.netTaskSocket.sendto(packet.to_bytes(), (self.destination_ip, self.destination_port))

        if task_type == 0:
            print(f"\nSent CPU METRICS to ip: {self.destination_ip} port: {self.destination_port}\n------")
        if task_type == 1:
            print(f"\nSent RAM METRICS to ip: {self.destination_ip} port: {self.destination_port}\n------")

        return packet.seq_num
    
    @staticmethod
    def isMETRICS(packet_type: int):
        if packet_type == 3:
            return True
        return False