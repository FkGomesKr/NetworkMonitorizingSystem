import subprocess
import time
import NetTask

class AgentUtils:
    @staticmethod
    def is_interface_active(interface_name):
        try:
            # Check if the interface exists and is up
            result = subprocess.run(
                ["ip", "link", "show", interface_name],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                print(f"Interface {interface_name} does not exist.")
                return False

            # Look for 'state UP' in the output to confirm the interface is active
            return "state UP" in result.stdout
        except Exception as e:
            print(f"Error checking interface {interface_name}: {e}")
            return False
        

    @staticmethod
    def get_packets_per_second(interface_name: str, duration: int):
        try:
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()

            # Extract interface stats
            def get_stats():
                for line in lines:
                    if line.strip().startswith(interface_name + ":"):
                        parts = line.split()
                        rx_packets = int(parts[1])  # Received packets
                        tx_packets = int(parts[9])  # Transmitted packets
                        return rx_packets, tx_packets
                return None

            # Get initial stats
            initial_stats = get_stats()
            if not initial_stats:
                print(f"Interface {interface_name} not found in /proc/net/dev.")
                return None

            time.sleep(duration)

            # Get stats after duration
            with open("/proc/net/dev", "r") as f:
                lines = f.readlines()
            final_stats = get_stats()

            if not final_stats:
                print(f"Interface {interface_name} not found in /proc/net/dev after duration.")
                return None

            # Calculate PPS
            rx_pps = (final_stats[0] - initial_stats[0]) / duration
            tx_pps = (final_stats[1] - initial_stats[1]) / duration
            total_pps = rx_pps + tx_pps
            return total_pps

        except Exception as e:
            print(f"Error measuring PPS for interface {interface_name}: {e}")
            return None

    @staticmethod
    def ints_to_ip(a: int, b: int, c: int, d: int) -> str:
        # Validate inputs
        for value in (a, b, c, d):
            if value < 0 or value > 255:
                raise ValueError(f"Each integer must be between 0 and 255, got {value}")

        # Construct the IP address string
        return f"{a}.{b}.{c}.{d}"

    @staticmethod
    def ip_to_ints(ip: str) -> tuple:
        # Split the IP string into its parts
        parts = ip.split(".")
        
        # Ensure the IP address has exactly 4 parts
        if len(parts) != 4:
            raise ValueError(f"Invalid IP address format: {ip}")
        
        # Convert each part to an integer and validate the range
        ints = []
        for part in parts:
            try:
                value = int(part)
            except ValueError:
                raise ValueError(f"Invalid IP address format: {ip}")
            
            if value < 0 or value > 255:
                raise ValueError(f"Each integer in the IP must be between 0 and 255, got {value}")
            
            ints.append(value)
        
        # Return the integers as a tuple
        return tuple(ints)
    
    @staticmethod
    def measure_latency(task_packet_count, host_destination_ip):

        avg_latency = 0 
        try:
            # Execute the ping command
            result = subprocess.run(
                ["ping", "-c", str(task_packet_count), host_destination_ip],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print(f"Ping failed: {result.stderr}")
                return avg_latency  # Return 0 if ping failed

            # Parse the output for latency values
            output = result.stdout
            lines = output.splitlines()
            latencies = []
            for line in lines:
                if "time=" in line:
                    # Extract latency from a line like: "64 bytes from x.x.x.x: icmp_seq=1 ttl=64 time=1.23 ms"
                    time_part = line.split("time=")[-1]
                    latency_ms = float(time_part.split(" ")[0])  # Extract the numeric latency value
                    latencies.append(latency_ms)

            # Calculate the average latency
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                print(f"Average latency: {avg_latency:.2f} ms")
            else:
                print("No valid latency measurements were found.")

        except Exception as e:
            print(f"Error during latency measurement: {e}")

        return avg_latency

    @staticmethod
    def run_iperf_server():
        try:
            print("Starting iperf in server mode...")
            result = subprocess.run(
                ["iperf", "-s", "-u", "-i", "1"],
                capture_output=True,
                text=True
            )
            print("Server output:\n", result.stdout)
        except Exception as e:
            print(f"Error running iperf server: {e}")

    @staticmethod
    def run_iperf_client(task_ip, task_duration, task_type, max_retries=5, retry_interval=5):
        retries = 0
        while retries < max_retries:
            try:
                time.sleep(5)
                print(f"Attempting to connect to iperf server at {task_ip} and measure {NetTask.NetTaskProtocol.taskType(task_type)}... (Attempt {retries + 1})")
                result = subprocess.run(
                    ["iperf", "-c", task_ip, "-u", "-t", str(task_duration), "-i", "1", "-b", "250K"],
                    capture_output=True,
                    text=True
                )

                if result.returncode == 0:
                    requested_metric = None
                    for line in result.stdout.splitlines():
                        # Parse jitter and packet loss
                        if "%" in line and "sec" in line:
                            try:
                                if task_type == 5 and "ms" in line:  # Jitter
                                    jitter_ms = float(line.split("ms")[0].split()[-1])
                                    requested_metric = jitter_ms
                                elif task_type == 6:  # Packet loss
                                    loss_percentage = line.split("(")[-1].split("%")[0].strip()
                                    requested_metric = float(loss_percentage)
                            except (IndexError, ValueError):
                                print(f"Could not parse metric from line: {line}")
                        # Parse throughput
                        elif "Kbits/sec" in line and task_type == 2:
                            try:
                                throughput = float(line.split("Kbits/sec")[0].split()[-1])
                                requested_metric = throughput
                            except (IndexError, ValueError):
                                print(f"Could not parse throughput from line: {line}")
                    print("Client output:\n", result.stdout)
                    return requested_metric
                else:
                    print(f"iperf client failed: {result.stderr}")
            except Exception as e:
                print(f"Error running iperf client: {e}")

            retries += 1
            if retries < max_retries:
                print(f"Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)

        print("Maximum retries reached. Could not connect to the iperf server.")
        return None

    @staticmethod
    def execute_task(task_mode, task_duration, task_ip, task_type):
        try:
            if task_mode == 1:  # Server mode
                AgentUtils.run_iperf_server()
                return 0
            else:  # Client mode
                metric = AgentUtils.run_iperf_client(task_ip, task_duration, task_type)
                if metric is not None:
                    metric_type = {5: "Jitter (ms)", 6: "Packet Loss (%)", 2: "Bandwidth (Kbits/sec)"}
                    print(f"Measured {metric_type[task_type]}: {metric:.2f}")
                    return metric
                else:
                    return 0
        except KeyboardInterrupt:
            print("Task execution interrupted by user.")
        except Exception as e:
            print(f"Error during task execution: {e}")





