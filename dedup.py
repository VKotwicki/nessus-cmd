import csv, re

# specify the input and output file names
input_file = "202212 - Workstation.csv"
output_file = "202212 - Workstation - output.csv"

# Vulnerability types to be removed
values_to_remove = ["Risk", "None", "Info", "Low"]

# the Name by the following values
split_pattern = r"[:<]"

# read the input file
with open(input_file, "r") as input_file:
    reader = csv.reader(input_file)
    lines = list(reader)

# write the output file, excluding lines that contain the specified value
with open(output_file, "w", encoding="utf-8", newline="") as output_file:
    writer = csv.writer(output_file)
    Headers = [
        "Risk",
        "Host",
        "Protocol",
        "Port",
        "Name",
        "CVSS v3.0 Base Score",
        "Risk Factor",
        "Application",
        "Version",
    ]
    writer.writerow(Headers)
    seen_lines = set()
    for line in lines:
        if not (line[0] in values_to_remove):
            tmpline = re.split(split_pattern, line[4])
            if len(tmpline) > 1:
                line.extend([tmpline[0], tmpline[1]])
            else:
                line.append(tmpline[0])
            line = tuple(line)
            if line not in seen_lines:
                writer.writerow(line)
                seen_lines.add(line)
