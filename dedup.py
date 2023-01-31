import csv, re
import argparse

# Takes in file name from cmd and can specify output file name
parser = argparse.ArgumentParser("Used for removing duplicate entries in Nessus csv files.")
parser.add_argument("-i", type=str, help="Input file name")
parser.add_argument("-o", type=str, help="Output file name") #TODO: make optional
args = parser.parse_args()


# specify the input and output file names
input_file = "202212 - Workstation.csv" # Can manually add your own here
if args.i:
    input_file = args.i

# format output file name
output_file = input_file[:-4] + " - output.csv" # Can manually add your own here

if args.o:
    output_file = args.o
    if args.o[-4:] != ".csv":
        output_file = output_file + ".csv"

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
