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

def load_logs(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".json":
        with open(file_path, "r") as f:
            return json.load(f)

    elif ext == ".csv":
        with open(file_path, newline="") as f:
            reader = csv.DictReader(f)
            return list(reader)

    elif ext == ".sml":
        tree = ET.parse(file_path)
        root = tree.getroot()
        return [child.attrib for child in root]

    else:
        raise ValueError("Unsupported file format. Use .json, .csv, or .sml")

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
    if "textPayload" in entry:
        message = entry["textPayload"]
    elif "jsonPayload" in entry:
        message = json.dumps(entry["jsonPayload"])
    elif "protoPayload" in entry:
        message = json.dumps(entry["protoPayload"])
    else:
        message = "No payload"

    event_class = event_class_override or determine_event_class(entry)
    class_info = OCSF_EVENT_CLASSES.get(event_class, OCSF_EVENT_CLASSES["custom_event"])

    normalized = {
        "time": entry.get("timestamp"),
        "severity_id": SEVERITY_MAP.get(entry.get("severity", "DEFAULT"), 1),
        "message": message,
        "source": "gcp",
        "event_class": event_class,
        "class_uid": class_info["class_uid"],
        "category_uid": class_info["category_uid"],
        "type_uid": class_info["type_uid"],
        "metadata": {
            "logName": entry.get("logName"),
            "insertId": entry.get("insertId"),
            "receiveTimestamp": entry.get("receiveTimestamp"),
            "resource": entry.get("resource", {}),
            "labels": entry.get("labels", {}),
            "trace": entry.get("trace"),
            "spanId": entry.get("spanId"),
            "traceSampled": entry.get("traceSampled")
        }
    }

    if "httpRequest" in entry:
        normalized["http"] = entry["httpRequest"]
    if "operation" in entry:
        normalized["operation"] = entry["operation"]
    if "sourceLocation" in entry:
        normalized["source_location"] = entry["sourceLocation"]
    if "split" in entry:
        normalized["split_info"] = entry["split"]

    return normalized

def convert_logs_to_ocsf(input_file):
    ext = os.path.splitext(input_file)[1]
    output_file = input_file.replace(ext, "_ocsf.json")

    raw_logs = load_logs(input_file)
    normalized_logs = []

    for idx, log in enumerate(raw_logs):
        if isinstance(log, dict):
            normalized_logs.append(normalize_logentry_to_ocsf(log))
        else:
            print(f"⚠️ Skipping log entry at index {idx} because it is not a dictionary: {type(log)}")

    with open(output_file, "w") as f:
        json.dump(normalized_logs, f, indent=2)

    print(f"✅ Converted {len(normalized_logs)} logs to OCSF format and saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Convert GCP logs to OCSF schema.")
    parser.add_argument("file", help="Path to input log file (.json, .csv, .sml)")
    args = parser.parse_args()
    convert_logs_to_ocsf(args.file)

if __name__ == "__main__":
    main()
