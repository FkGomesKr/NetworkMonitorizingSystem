import struct
import NetTask

class AlertFlowPacket:
    def __init__(self, seq_num: int, task_type: int, task_threshold: int, metric_value: int):
        # Validate inputs
        if seq_num >= 256:
            raise ValueError("seq_num must be less than 256 (fits in 8 bits)")
        if task_type >= 8:
            raise ValueError("task_type must be less than 8 (fits in 3 bits)")
        
        self.seq_num = seq_num
        self.task_type = task_type
        self.task_threshold = task_threshold
        self.metric_value = metric_value
        
    def to_bytes(self) -> bytes:
        packet = struct.pack("!B", self.seq_num)
        packet += struct.pack("!B", self.task_type)
        packet += struct.pack("!H", self.task_threshold)

        # Encode metric_value
        if self.metric_value <= 255:  # Fits in 1 bytes
            packet += struct.pack("!B", self.metric_value)
        elif self.metric_value <= 65535:  # Fits in 2 bytes
            packet += struct.pack("!H", self.metric_value)
        else:  # Requires 3 bytes
            packet += struct.pack("!I", self.metric_value)[1:]  # Take the last 3 bytes

        print(f"Sent AlertFlow Alert! Metric sequence number: {self.seq_num}")
        return packet

    @classmethod
    def from_bytes(cls, data: bytes):
        # Ensure the input data length is sufficient
        if len(data) < 5:  # Minimum required length for packet_type, seq_num, task_type, task_threshold, and metric_value
            raise ValueError("Insufficient data to decode AlertFlowPacket")

        # Decode fields in the same order as `to_bytes`
        offset = 0

        seq_num = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_type = struct.unpack("!B", data[offset:offset + 1])[0]
        offset += 1

        task_threshold = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

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

        # Return a new instance of AlertFlowPacket
        return cls(seq_num, task_type, task_threshold, metric_value)


    def print_packet(self, source_ip: str, source_port: str):
        print(f"Packet TCP AlertFlow received from IP {source_ip} and port {source_port}")
        print(f"Packet type: ALERT")
        print(f"Sequence number: {self.seq_num}")
        print(f"Task type: {self.task_type} which is {NetTask.NetTaskProtocol.taskType(self.task_type)}")
        if (self.task_type == 0 or self.task_type == 1 or self.task_type == 6 or self.task_type == 2):
            print(f"Metric value: {self.metric_value}%")
            print(f"Task threshold value: {self.task_threshold}%")
        elif (self.task_type == 4):
            print(f"Metric value: {self.metric_value} pps")
            print(f"Task threshold value: {self.task_threshold} pps")
        elif (self.task_type == 3 or self.task_type == 5):
            print(f"Metric value: {self.metric_value} ms")
            print(f"Task threshold value: {self.task_threshold} ms")
        

        else: print(f"Metric value: {self.metric_value}")
        print("-------------------")

    