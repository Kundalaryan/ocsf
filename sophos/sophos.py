import json
import csv
import os
import xml.etree.ElementTree as ET
import argparse

# Severity mapping (GCP -> OCSF)
SEVERITY_MAP = {
    "DEFAULT": 1,
    "DEBUG": 2,
    "INFO": 3,
    "NOTICE": 4,
    "WARNING": 5,
    "ERROR": 6,
    "CRITICAL": 7,
    "ALERT": 8,
    "EMERGENCY": 9
}

# OCSF Event Class Mapping
OCSF_EVENT_CLASSES = {
    "network_activity": {"class_uid": 1, "category_uid": 1, "type_uid": 1001},
    "authentication": {"class_uid": 2, "category_uid": 2, "type_uid": 2001},
    "audit": {"class_uid": 3, "category_uid": 3, "type_uid": 3001},
    "application_activity": {"class_uid": 4, "category_uid": 4, "type_uid": 4001},
    "custom_event": {"class_uid": 0, "category_uid": 0, "type_uid": 9999}
}

SOPHOS_KNOWN_ATTRIBUTES = [
    "log_type", "log_component", "log_subtype", "log_version",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "src_zone", "dst_zone", "src_country", "dst_country",
    "protocol", "con_direction", "fw_rule_id",
    "user_name", "user_group", "device_name", "device_model", "device_serial_id",
    "file_name", "file_size", "file_path", "url", "dstdomain",
    "malware", "ftpcommand", "sent_bytes", "recv_bytes", "log_id",
    "application", "icmp_type", "icmp_code", "policy_id", "rule_type",
    "rule_name", "service_name", "action", "in_interface", "out_interface"
]

def load_logs(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".json":
        with open(file_path, "r") as f:
            return json.load(f)

    elif ext == ".csv":
        with open(file_path, newline="") as f:
            reader = csv.DictReader(f)
            return list(reader)

    elif ext == ".xml":
        tree = ET.parse(file_path)
        root = tree.getroot()
        return [child.attrib for child in root]

    else:
        raise ValueError("Unsupported file format. Use .json, .csv, or .xml")

def determine_event_class(entry):
    if "httpRequest" in entry:
        return "network_activity"
    elif "protoPayload" in entry and "authenticationInfo" in json.dumps(entry["protoPayload"]):
        return "authentication"
    elif "resource" in entry and entry["resource"].get("type", "").lower() in ["gce_instance", "iam_user"]:
        return "audit"
    else:
        return "custom_event"

def normalize_logentry_to_ocsf(entry, event_class_override=None):
    message = entry.get("message", "No payload")
    event_class = event_class_override or determine_event_class(entry)
    class_info = OCSF_EVENT_CLASSES.get(event_class, OCSF_EVENT_CLASSES["custom_event"])

    sophos_details = {k: entry.get(k, None) for k in SOPHOS_KNOWN_ATTRIBUTES}
    additional_fields = {k: v for k, v in entry.items() if k not in SOPHOS_KNOWN_ATTRIBUTES + ["timestamp", "severity", "message", "hostname", "process"]}
    sophos_details.update(additional_fields)

    normalized = {
        "time": entry.get("timestamp"),
        "severity_id": SEVERITY_MAP.get(entry.get("severity", "INFO"), 3),
        "message": message,
        "source": "sophos",
        "event_class": event_class,
        "class_uid": class_info["class_uid"],
        "category_uid": class_info["category_uid"],
        "type_uid": class_info["type_uid"],
        "metadata": {
            "hostname": entry.get("hostname"),
            "process": entry.get("process")
        },
        "sophos_details": sophos_details
    }

    return normalized

def convert_logs_to_ocsf(input_file, output_file, event_class_override=None):
    raw_logs = load_logs(input_file)
    normalized_logs = []

    for idx, log in enumerate(raw_logs):
        if isinstance(log, dict):
            normalized_logs.append(normalize_logentry_to_ocsf(log, event_class_override))
        else:
            print(f"⚠️ Skipping log entry at index {idx} because it is not a dictionary: {type(log)}")

    with open(output_file, "w") as f:
        json.dump(normalized_logs, f, indent=2)

    print(f"✅ Converted {len(normalized_logs)} logs to OCSF format and saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Convert Sophos logs to OCSF schema.")
    parser.add_argument("file", help="Path to input log file (.json, .csv, .xml)")
    args = parser.parse_args()

    output_path = os.path.splitext(args.file)[0] + "_ocsf.json"
    convert_logs_to_ocsf(args.file, output_path)

if __name__ == "__main__":
    main()
