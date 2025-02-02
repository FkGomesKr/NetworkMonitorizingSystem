import datetime
import os
import json
import NetTask
import AlertFlow
import NetTask
import shutil
import utils

class DatabaseHandler:

    def delete_directory(directory: str = "../../../home/core/CC-TP2/Database"):
        if not os.path.exists(directory):
            print(f"Directory '{directory}' does not exist.")
            return

        try:
            shutil.rmtree(directory)
            print(f"Deleted directory: {directory}")
        except Exception as e:
            print(f"Error deleting directory '{directory}': {e}")


    @staticmethod
    def initialize_agent_file(agent_id: str, ip: str, file_path: str = "../../../home/core/CC-TP2/Database"):
        # Ensure the file path exists
        os.makedirs(file_path, exist_ok=True)

        # JSON file name and path
        json_file_name = f"{agent_id}.json"
        json_file_path = os.path.join(file_path, json_file_name)

        # If the file does not exist, create it with the correct structure
        if not os.path.exists(json_file_path):
            initial_data = {
                "agent_id": agent_id,
                "ip": ip,
                "metrics_and_alerts": []
            }
            with open(json_file_path, "w") as json_file:
                json.dump(initial_data, json_file, indent=4)
            print(f"Initialized JSON file for agent: {agent_id}")
        else:
            # Validate the existing file structure
            with open(json_file_path, "r") as json_file:
                try:
                    data = json.load(json_file)
                    if not isinstance(data, dict) or "metrics_and_alerts" not in data:
                        raise ValueError("Invalid JSON structure. Reinitializing file.")
                except (json.JSONDecodeError, ValueError):
                    # Reinitialize the file if it's invalid
                    initial_data = {
                        "agent_id": agent_id,
                        "ip": ip,
                        "metrics_and_alerts": []
                    }
                    with open(json_file_path, "w") as json_file:
                        json.dump(initial_data, json_file, indent=4)
                    print(f"Reinitialized JSON file for agent: {agent_id}")

        return json_file_path
    
    @staticmethod
    def save_metric_to_json(agent_id: str, ip: str, metric_packet: NetTask.NetTaskMETRICSPacket, dest_agent_id: str, dest_ip: int, file_path: str = "../../../home/core/CC-TP2/Database"):
        json_file_path = DatabaseHandler.initialize_agent_file(agent_id, ip, file_path)

        # Prepare the metric data to save
        timestamp = datetime.datetime.now().isoformat()

        metric_termination = ''
        if metric_packet.task_type == 0 or metric_packet.task_type == 1 or metric_packet.task_type == 6:  
            metric_termination = '%'
        elif metric_packet.task_type == 3 or metric_packet.task_type == 5:  
            metric_termination = 'ms'
        elif metric_packet.task_type == 4:  
            metric_termination = 'pps'
        elif metric_packet.task_type == 2:  
            metric_termination = 'Kbits/sec'

        metric_data = {
            "type": "error"
        }

        if (not (metric_packet.task_server_ip_1 == 0 and metric_packet.task_server_ip_2 == 0 and metric_packet.task_server_ip_3 == 0 and metric_packet.task_server_ip_4 == 0)):
            metric_data = {
                "type": "metric",
                "timestamp": timestamp,
                "packet_data": {
                    "seq_num": metric_packet.seq_num,
                    "task_type": NetTask.NetTaskProtocol.taskType(metric_packet.task_type),
                    "server_adress": f"{dest_ip} | {dest_agent_id}",
                    "metric_value": f"{metric_packet.metric_value} {metric_termination}"
                }
            }

        else:
            metric_data = {
                "type": "metric",
                "timestamp": timestamp,
                "packet_data": {
                    "seq_num": metric_packet.seq_num,
                    "task_type": NetTask.NetTaskProtocol.taskType(metric_packet.task_type),
                    "metric_value": f"{metric_packet.metric_value} {metric_termination}"
                }
            }

        # Append the new metric data
        try:
            with open(json_file_path, "r+") as json_file:
                try:
                    data = json.load(json_file)
                except json.JSONDecodeError as e:
                    print(f"Error reading JSON file: {e}")
                    data = {"agent_id": agent_id, "ip": ip, "metrics_and_alerts": []}

                data["metrics_and_alerts"].append(metric_data)

                # Write updated data back to file
                json_file.seek(0)
                json.dump(data, json_file, indent=4)
                json_file.truncate()  # Ensure no leftover data remains
                print(f"Metric saved to {json_file_path}")
        except Exception as e:
            print(f"Error saving metric data: {e}")

    @staticmethod
    def save_alert_to_json(agent_id: str, ip: str, alert_packet: AlertFlow.AlertFlowPacket, file_path: str = "../../../home/core/CC-TP2/Database"):
        json_file_path = DatabaseHandler.initialize_agent_file(agent_id, ip, file_path)

        # Prepare the alert data to save
        timestamp = datetime.datetime.now().isoformat()

        alert_termination = ''
        if alert_packet.task_type == 0 or alert_packet.task_type == 1 or alert_packet.task_type == 6:  
            alert_termination = '%'
        elif alert_packet.task_type == 3 or alert_packet.task_type == 5:  
            alert_termination = 'ms'
        elif alert_packet.task_type == 4:  
            alert_termination = 'pps'
        elif alert_packet.task_type == 2:  
            alert_termination = 'Kbits/sec'

        alert_data = {
            "type": "alert",
            "timestamp": timestamp,
            "alert_data": {
                "seq_num": alert_packet.seq_num,
                "task_type": NetTask.NetTaskProtocol.taskType(alert_packet.task_type),
                "task_threshold": f"{alert_packet.task_threshold} {alert_termination}",
                "metric_value": f"{alert_packet.metric_value} {alert_termination}"
            }
        }

        # Append the new alert data
        try:
            with open(json_file_path, "r+") as json_file:
                try:
                    data = json.load(json_file)
                except json.JSONDecodeError as e:
                    print(f"Error reading JSON file: {e}")
                    data = {"agent_id": agent_id, "ip": ip, "metrics_and_alerts": []}

                data["metrics_and_alerts"].append(alert_data)

                # Write updated data back to file
                json_file.seek(0)
                json.dump(data, json_file, indent=4)
                json_file.truncate()  # Ensure no leftover data remains
                print(f"Alert saved to {json_file_path}")
        except Exception as e:
            print(f"Error saving alert data: {e}")