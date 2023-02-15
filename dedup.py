import csv, re
import argparse
from datetime import datetime
import time

# TODO:
# Deal with dates
# deal with multiple versions
# deal with the "multiple" - remove it?

# Takes in file name from cmd and can specify output file name
parser = argparse.ArgumentParser("Used for removing duplicate entries in Nessus csv files.")
parser.add_argument("-i", type=str, help="Input file name")
parser.add_argument("-o", type=str, help="Output file name") #TODO: make optional
args = parser.parse_args()


# specify the input and output file names
if args.i:
    input_file = args.i
else:
    now  = datetime.now()
    now_formatted = now.strftime("%d-%m-%Y %H-%M-%S")
    input_file = "results" + now_formatted + ".csv" # Can manually add your own here

# format output file name
output_file = input_file[:-4] + " - output.csv" # Can manually add your own here

if args.o:
    output_file = args.o
    if args.o[-4:] != ".csv":
        output_file = output_file + ".csv"

# TODO: checks port and IP before
# OUTPUT: "New Updated Row", whether it is similar or not
# RETURNS: "New Updated Row", whether it is similar or not
# Examples:
# INPUT: "Google Chrome 10.2.6.1", "Google Chrome 11.3.9.1 / 12.2.2.2"
# OUTPUT:"Google Chrome 12.2.2.2"
# INPUT: "Google Chrome 10.2.6.1", "Chromium 11.3.9.1 / 12.2.2.2"
# OUTPUT:"Chromium 12.2.2.2"
def check_similar_rows(master_name_cell, comparison_name_cell):
    # TODO: account for sates in the (January 2023) format
    # If the next word after the version number is the same

    reg = "((?=\d+\.)+[(\.\d+a-z)]+)"
    versions_master = re.findall(reg, master_name_cell)
    versions_comparison =  re.findall(reg, comparison_name_cell)

    versions = versions_master + versions_comparison

    if versions != [] and versions != None:

        formatted_master_str = master_name_cell.replace("/", " ")
        formatted_comparison_str = comparison_name_cell.replace("/", " ")
        
        # This creates a placeholder for adding in the highest version string later
        if versions_master:
            formatted_master_str = formatted_master_str.replace(versions_master[0], "***")
        if versions_comparison:
            formatted_comparison_str = formatted_comparison_str.replace(versions_comparison[0], "***")

        for i in versions:
            formatted_master_str =  formatted_master_str.replace(i, "")
            formatted_comparison_str = formatted_comparison_str.replace(i, "")

        formatted_master_str = re.sub(" +", " ", formatted_master_str) # remove any excessive whitespaces left over
        formatted_comparison_str = re.sub(" +", " ", formatted_comparison_str) # remove any excessive whitespaces left over

        # First, get max verisons within each cell
        
        if formatted_master_str == formatted_comparison_str:
            # same string with different versions
            # so, get most updated version and insert into the new one, and return that
            highest_version = max(versions)

            # Because we had to remove the dots to check for the highest version available, it's not formatted correctly
            # so, we find the correctly formated version (with the .) and use that one instead to add back in
            formatted_master_str = formatted_master_str.replace("***", highest_version)

            #print("old master:", master_name_cell)
            #print("old comp:", comparison_name_cell)
            #print(formatted_master_str)

            return (formatted_master_str, True)

        if versions_comparison:
            highest_version = max(versions_comparison)
            comparison_name_cell = formatted_comparison_str.replace("***", highest_version)

    return (comparison_name_cell, False)



# Vulnerability types to be removed
values_to_remove = ["Risk", "None", "Info", "Low"]

# the Name by the following values
split_pattern = r"[:<]"

# read the input file
with open(input_file, "r", encoding="utf-8") as input_file:
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
        "Solution",
        "CVSS v3.0 Base Score",
        "Risk Factor",
        "Application",
        "Version",
    ]
    writer.writerow(Headers)
    seen_lines = set()
    data = []
    last_row_set = ""
    current_updated_cell = ""
    rows_to_update = []
    data_index = 0
    for line in lines:
        if not (line[0] in values_to_remove):
            tmpline = re.split(split_pattern, line[4])
            if len(tmpline) > 1:
                line.extend([tmpline[0], tmpline[1]])
            else:
                line.append(tmpline[0])
            line = tuple(line)
            if line not in seen_lines:
                # TODO: move this logic to its own section

                # If current cell is similar to the last cell set checked, this will return the last cell checked with the higher version number as part of the string
                # This returns a tuple with the updated cell value and a bool that states whether this cell is similar to the last set one
                current_updated_cell = check_similar_rows(last_row_set, line[4])
                temp_list = list(line)
                temp_list[4] = current_updated_cell[0]
                line = tuple(temp_list)        
                
                if not current_updated_cell[1]:
                    # TODO: check if any previous rows to update
                    #print(data)
                    if len(rows_to_update) > 1:
                        index_to_update = rows_to_update.pop(0) # remove lowest one
                        rows_to_update.sort(reverse=True) # if not from highest to lowest, index will be out of range for some cases
                        temp_list = list(data[index_to_update])
                        temp_list[4] = last_row_set
                        data[index_to_update] = tuple(temp_list)
                        
                        # since it's
                        for i in rows_to_update: # previous now duplicate entries
                            del data[i]
                            data_index = data_index - 1

                    # if they aren't similar at all
                    rows_to_update = []

                last_row_set = current_updated_cell[0]
                rows_to_update.append(data_index) # rows to update if multiple cells are similar
                # e.g. Google Chrome 10.10.3.2 == Google Chrome 10.10.3.2
                # e.g. Google Chrome 10.10.3.2 == Acrobat 2.10.9.1
                #if current_updated_cell == last_row_set:


                # line[4] = "updated value"

                data.append(line)
                # writer.writerow(line) # move this to the end
                seen_lines.add(line)

                data_index = data_index + 1

    for row in data:
        writer.writerow(row)


# TODO: look for versions using regex (num and .) and dates to find dupes
# order matters? do only for consecutive rows
# to check versions, remove dots and return highest one
# to check dates, convert to numbers -> year then month
# if different IP, restart check
#if different port, restart check

# use calendar module?
months_to_num = {
    "January": 1,
    "February": 2,
    "March": 3,
    "April": 4,
    "May": 5,
    "June": 6,
    "July": 7,
    "August": 8,
    "September": 9,
    "October": 10,
    "November": 11,
    "December": 12
}



