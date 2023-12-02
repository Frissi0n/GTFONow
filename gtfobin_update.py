#!/usr/bin/env python3
import os
import json
import yaml

GTFOBINS_PATH = "GTFOBins.github.io/_gtfobins/"
GTFO_NOW_PATH = "gtfonow/gtfonow.py"


def replace_content(file_path, new_content, start_marker, end_marker):
    """Replace content in a file between start_marker and end_marker."""
    try:
        with open(file_path, 'r') as file:
            content = file.readlines()

        start_index = next((i for i, line in enumerate(
            content) if start_marker in line), None)
        end_index = next((i for i, line in enumerate(
            content) if end_marker in line), None)

        if start_index is not None and end_index is not None:
            content = content[:start_index + 1] + \
                [new_content + '\n'] + content[end_index:]
            with open(file_path, 'w') as file:
                file.writelines(content)
        else:
            print("Markers not found in file")
    except IOError as e:
        print(f"Error opening file: {e}")


def process_yaml(filename, key):
    """Process YAML file and extract data for a specific key."""
    with open(filename, 'r') as f:
        content = f.read().replace("---", "")
        doc = yaml.load(content, Loader=yaml.Loader)
        if key in doc["functions"]:
            binary = os.path.basename(filename).replace(".md", "")
            return binary, [payload["code"] for payload in doc["functions"][key]]
    return None, None


def main():
    sudo_bins = {}
    suid_bins = {}
    capabilities = {}

    for filename in os.listdir(GTFOBINS_PATH):
        if not filename.endswith(".md"):
            continue
        full_path = os.path.join(GTFOBINS_PATH, filename)
        for key in ["sudo", "suid", "capabilities"]:
            binary, payloads = process_yaml(full_path, key)
            if binary and payloads:
                if key == "sudo":
                    sudo_bins[binary] = payloads
                elif key == "suid":
                    suid_bins[binary] = payloads
                elif key == "capabilities":
                    capabilities[binary] = payloads

    replace_content(GTFO_NOW_PATH, "sudo_bins=" + json.dumps(sudo_bins,
                    indent=4), "# SUDO_BINS_START", "# SUDO_BINS_END")
    replace_content(GTFO_NOW_PATH, "suid_bins=" + json.dumps(suid_bins,
                    indent=4), "# SUID_BINS_START", "# SUID_BINS_END")
    replace_content(GTFO_NOW_PATH, "capabilities=" + json.dumps(capabilities,
                    indent=4), "# CAPABILITIES_START", "# CAPABILITIES_END")


if __name__ == "__main__":
    main()
