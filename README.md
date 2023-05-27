# **MATCHO-PIDS**

## Description
The MATCHO-PIDS is an automation tool that match between containers and host PIDs.

# Installation Requirements
Python version 3

# Install MATCHO-PIDS
git clone https://github.com/OfriOuzan/MATCHO-PIDS

# Execute MATCHO-PIDS
cd matcho-pids

python3 matcho-pids.py

# Arguments

## -p --pids
Get a list of host processes PIDs to be matched with container PIDs

## -f --format
Specify output formatter: csv or text, default is text (when format is csv the output is saved to output.csv)

# Template of executing MATCHO-PIDS with arguments
python3 matcho-pids.py -p <pid_number> <pid_number> -f csv
