import json

class JsonReader:
    @staticmethod
    def load(file_path="../../../home/core/CC-TP2/config.json"):
        try:
            with open(file_path, mode='r', encoding='utf-8') as file:
                data = json.load(file)
            return data
        except FileNotFoundError:
            print(f"Error: The file '{file_path}' was not found.")
        except json.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        return None
    
    @staticmethod
    def get_tasks_length(data):
        if "tasks" in data and isinstance(data["tasks"], list):
            return len(data["tasks"])
        print("Error: 'tasks' key is missing or is not a list.")
        return 0
    
    @staticmethod
    def get_task_by_index(data, index):
        try:
            if "tasks" in data and isinstance(data["tasks"], list):
                return data["tasks"][index]
            print("Error: 'tasks' key is missing or is not a list.")
        except IndexError:
            print(f"Error: Index {index} is out of range.")
        return None

    @staticmethod
    def validate_task_devices(task, registered_agents):
        # Extract all device_ids from the task
        task_device_ids = [device["device_id"] for device in task["devices"]]
        
        # Check if all device_ids are in the registered_agents list
        return all(device_id in registered_agents for device_id in task_device_ids)
    
    @staticmethod
    def get_device_instructions_by_id(task, device_id):
        # Iterate over all devices in the task
        for device in task["devices"]:
            # Check if the current device has a "device_id" key and if it matches the input device_id
            if "device_id" in device and device["device_id"] == device_id:
                return device  # Return the matching device object
        return None  # Return None if no matching device is found
    
    @staticmethod
    def get_device_interface_stats(task, device_id):
        try:
            for device in task["devices"]:
                if device["device_id"] == device_id:
                    return device["device_metrics"]["interface_stats"]
        except KeyError as e:
            print(f"Key error: {e}")
        return None
    
    @staticmethod
    def get_alertflow(task, device_id: str):
        try:
            for device in task["devices"]:
                if device["device_id"] == device_id:
                    return device["alertflow_conditions"]
        except KeyError as e:
            print(f"Key error: {e}")
        return None
    
    @staticmethod
    def get_latency_object(task, device_id: str):
        if "devices" not in task:
            raise ValueError("Task does not contain any devices.")
        
        for device in task["devices"]:
            if "device_id" in device and device["device_id"] == device_id:
                if "link_metrics" in device and "latency" in device["link_metrics"]:
                    return device["link_metrics"]["latency"]
                raise ValueError(f"Latency object not found for device_id: {device_id}")
        
        raise ValueError(f"Device with device_id '{device_id}' not found in task")
    
    @staticmethod
    def get_packet_loss_object(task, device_id: str):
        if "devices" not in task:
            raise ValueError("Task does not contain any devices.")
        
        for device in task["devices"]:
            if "device_id" in device and device["device_id"] == device_id:
                if "link_metrics" in device and "latency" in device["link_metrics"]:
                    return device["link_metrics"]["packet_loss"]
                raise ValueError(f"Packet loss object not found for device_id: {device_id}")
        
        raise ValueError(f"Device with device_id '{device_id}' not found in task")
    
    @staticmethod
    def get_jitter_object(task, device_id: str):
        if "devices" not in task:
            raise ValueError("Task does not contain any devices.")
        
        for device in task["devices"]:
            if "device_id" in device and device["device_id"] == device_id:
                if "link_metrics" in device and "latency" in device["link_metrics"]:
                    return device["link_metrics"]["jitter"]
                raise ValueError(f"Packet loss object not found for device_id: {device_id}")
        
        raise ValueError(f"Device with device_id '{device_id}' not found in task")
    
    @staticmethod
    def get_throughput_object(task, device_id: str):
        if "devices" not in task:
            raise ValueError("Task does not contain any devices.")
        
        for device in task["devices"]:
            if "device_id" in device and device["device_id"] == device_id:
                if "link_metrics" in device and "latency" in device["link_metrics"]:
                    return device["link_metrics"]["bandwidth"]
                raise ValueError(f"Packet loss object not found for device_id: {device_id}")
        
        raise ValueError(f"Device with device_id '{device_id}' not found in task")
