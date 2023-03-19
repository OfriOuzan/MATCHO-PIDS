import argparse
import subprocess
import shlex
import os
import csv


def csv_format(matched_pids):
    """This function writes the output to a csv file called output.csv."""
    with open('output.csv', 'w') as file:
        writer = csv.writer(file)
        header = ['Host PID', 'Container PID']
        writer.writerow(header)
        for matched_pid in matched_pids:
            writer.writerow(matched_pid)


def text_format(matched_pids):
    """This function prints the matched process IDs to stdout."""
    print("Host PID, Container PID")
    for matched_pid in matched_pids:
        print(f"{matched_pid[0]}, {matched_pid[1]}")


def running_command(command):
    """This function returns the output of a running os command."""
    split_command = shlex.split(command)
    pipe = subprocess.run(split_command, capture_output=True, text=True)
    return pipe.stdout


def check_matched_container(pids):
    """This function returns the potential pids from the relevant container."""
    if not os.path.isdir('/'):
        print('The "/" directory does not exist')
        return []
    get_root_directory_command = 'ls /'
    root_directory_output = running_command(get_root_directory_command)
    if not root_directory_output:
        print(f'Error running {get_root_directory_command} command')
    container_pids = []
    for pid in pids:
        if not pid.isdigit():
            print(f'The {pid} is not a valid PID, PIDs need to be only digits')
            continue
        get_process_root_directory_command = f'ls /proc/{pid}/root'
        try:
            process_root_directory_output = running_command(get_process_root_directory_command)
        except FileNotFoundError:
            print(f'The "{get_process_root_directory_command}" file does not exist')
            continue
        if process_root_directory_output and process_root_directory_output != root_directory_output:
            container_pids.append(pid)
    return container_pids


def check_matched_pids(pids):
    """This function returns the matched host pids to container pids."""
    container_pids = check_matched_container(pids)
    if not container_pids:
        print('You do not have any running containers')
        return []
    containers_pids = []
    for pid in container_pids:
        if not os.path.isfile(f'/proc/{pid}/status'):
            print(f'The "/proc/{pid}/status" file does not exist')
            return []
        pid_status_file_path = f'/proc/{pid}/status'
        pid_status_file = open(pid_status_file_path, 'r')
        content = pid_status_file.read().split('\n')
        container_pid = [line.split('\t')[-1] for line in content if line.startswith('NSpid:') and len(line.split('\t')) == 3]
        if container_pid:
            containers_pids.append([pid, container_pid[0]])
    return containers_pids


def get_running_pids():
    """This function gets the running processes ids."""
    get_running_pids_command = 'ps -A -o pid'
    running_pids_output = running_command(get_running_pids_command)
    running_pids_content = running_pids_output.split('\n')[1:]
    pids = [pid.replace(' ', '') for pid in running_pids_content if pid != '']
    return pids


def arguments():
    """This function sets the arguments."""
    parser = argparse.ArgumentParser(description="'AM I Exploitable?' is a service that let's you validate "
                                                 "whether or not your system is susceptible to a given CVE")
    parser.add_argument('-p', '--pids', type=str, nargs='+', default=False, help='Get a list host processes PIDs to be '
                                                                                 'matched with container PIDs')
    parser.add_argument('-f', '--format', type=str, default='text', help='Specify output formatter: csv or text, default'
                                                                         'is text (when format is csv the output is '
                                                                         'saved to output.csv)')
    return parser.parse_args()


def main():
    args = arguments()
    pids = args.pids
    if not pids:
        pids = get_running_pids()
    output_format = args.format
    matched_pids = check_matched_pids(pids)
    if matched_pids:
        if not output_format or output_format.lower() == 'text':
            text_format(matched_pids)
        elif output_format.lower() == 'csv':
            csv_format(matched_pids)
        else:
            print('Format needs to be text or csv')


if __name__ == '__main__':
    main()
