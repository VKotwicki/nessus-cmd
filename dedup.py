import csv, re
from doctest import master


# TODO: checks port and IP before
# OUTPUT: "New Updated Row", whether it is similar or not
# RETURNS: "New Updated Row", whether it is similar or not
# Examples:
# INPUT: "Google Chrome 10.2.6.1", "Google Chrome 11.3.9.1 / 12.2.2.2"
# OUTPUT:"Google Chrome 12.2.2.2"
# INPUT: "Google Chrome 10.2.6.1", "Chromium 11.3.9.1 / 12.2.2.2"
# OUTPUT:"Chromium 12.2.2.2"
def check_similar_rows(master_name_cell, comparison_name_cell):
    # If same up to date or version
    # If everything BUT the numbers are the same (or dates), return updated master list
    
    # TODO: account for sates in the (January 2023) format
    # If the next word after the version number is the same
    
    # TODO: use regex to remove versions/dates from a string and see if they're the same

    # This removes the ugly tuple results caused by regex groups
    # TODO: find a better way to do this - regex needs fixing
    reg = "((?=\d+\.)+[(\.\d+a-z)]+)"
    versions_master = re.findall(reg, master_name_cell)
    versions_comparison =  re.findall(reg, comparison_name_cell)

    versions = versions_master + versions_comparison

    # only used to see if both strings are the same when the versions are removed
    # make a different version of the string for the comparison bit
    # then get the string that has the highest version, then just remove the lower verisons using the regex
    formatted_master_str = master_name_cell
    formatted_comparison_str = comparison_name_cell
    for i in versions:
        formatted_master_str =  formatted_master_str.replace(i, "***")
        formatted_comparison_str = formatted_comparison_str.replace(i, "***")

    if versions:
        if formatted_master_str == formatted_comparison_str:
            # same string with different versions
            # so, get most updated version and insert into the new one, and return that
            highest_version = max(versions)

            # Because we had to remove the dots to check for the highest version available, it's not formatted correctly
            # so, we find the correctly formated version (with the .) and use that one instead to add back in
            formatted_master_str = formatted_master_str.replace("***", highest_version, 1)
            re.sub("[\\/*]", "", formatted_master_str) # removes extra * and any leftover /
            re.sub(" +", " ", formatted_master_str) # remove any excessive whitespaces left over

            #print("old master:", master_name_cell)
            #print("old comp:", comparison_name_cell)
            #print(formatted_master_str)

            return (formatted_master_str, True)

    return (comparison_name_cell, False)



# specify the input and output file names
input_file = "Servers Credential Scan (KEELE)_c99g1e.csv"
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
                # If they are similar
                # current_updated_cell[1] is a bool - whether the cells are similar or not
                #print("LINE:", line)
                #print("")
                #print("Similar?:", current_updated_cell[1]) 
                # if they arent similar, run the below code and reset rows_to_update
                # if they are similar, rows_to_update shouldnt reset
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

                rows_to_update.append(data_index) # rows to update if multiple cells are similar
                last_row_set = current_updated_cell[0]
                # e.g. Google Chrome 10.10.3.2 == Google Chrome 10.10.3.2
                # e.g. Google Chrome 10.10.3.2 == Acrobat 2.10.9.1
                #if current_updated_cell == last_row_set:


                # line[4] = "updated value"

                data.append(line)
                # writer.writerow(line) # move this to the end
                seen_lines.add(line)

                data_index = data_index + 1

        if data_index == 5000:
            for i in data:
                #print(i)
                pass
            break

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



