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

def parse_json_field(field):
    if isinstance(field, str):
        try:
            return json.loads(field)
        except:
            return {}
    return field or {}

def load_logs(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".json":
        with open(file_path, "r") as f:
            return json.load(f)

    elif ext == ".csv":
        with open(file_path, newline="") as f:
            reader = csv.DictReader(f)
            return list(reader)

    elif ext in [".sml", ".xml"]:
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
    elif "resource" in entry and parse_json_field(entry["resource"]).get("type", "").lower() in ["gce_instance", "iam_user"]:
        return "audit"
    else:
        return "custom_event"

def normalize_logentry_to_ocsf(entry, event_class_override=None):
    resource = parse_json_field(entry.get("resource"))
    labels = parse_json_field(entry.get("labels"))
    proto = parse_json_field(entry.get("protoPayload"))
    json_payload = parse_json_field(entry.get("jsonPayload"))
    http = parse_json_field(entry.get("httpRequest"))

    if "textPayload" in entry:
        message = entry["textPayload"]
    elif json_payload:
        message = json.dumps(json_payload)
    elif proto:
        message = json.dumps(proto)
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
            "resource": resource,
            "labels": labels,
            "trace": entry.get("trace"),
            "spanId": entry.get("spanId"),
            "traceSampled": entry.get("traceSampled"),
            "sourceLocation": parse_json_field(entry.get("sourceLocation")),
            "operation": parse_json_field(entry.get("operation")),
            "httpRequest": http,
            "protoPayload": proto,
            "jsonPayload": json_payload,
            "textPayload": entry.get("textPayload"),
            "split": parse_json_field(entry.get("split")),
            "severity": entry.get("severity"),
            "timestamp": entry.get("timestamp"),
            "receiveTimestamp": entry.get("receiveTimestamp"),
            "resourceType": resource.get("type"),
            "resourceLabels": resource.get("labels")
        },
        "raw_log": entry
    }

    if http:
        normalized["http_method"] = http.get("requestMethod")
        normalized["http_url"] = http.get("requestUrl")
        normalized["http_status"] = http.get("status")
        normalized["http_userAgent"] = http.get("userAgent")

    if proto:
        normalized["proto_serviceName"] = proto.get("serviceName")
        normalized["proto_methodName"] = proto.get("methodName")
        normalized["proto_auth"] = parse_json_field(proto.get("authenticationInfo")).get("principalEmail")

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
    parser.add_argument("file", help="Path to input log file (.json, .csv, .xml)")
    args = parser.parse_args()
    convert_logs_to_ocsf(args.file)

if __name__ == "__main__":
    main()
