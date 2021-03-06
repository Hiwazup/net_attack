<b>Assignment Summary</b>

The net_attack.py script will automate the process of discovering weak usernames and passwords
being used for services running on a host. The script will read a file containing a list of IP addresses.
For each IP address in the list the script will scan the ports on that host, and attempt to bruteforce
the login for detected services.

The script will take in the following parameters:

  -t -> Filename for a file containing a list of IP addresses
  
  -p -> Ports to scan on the target host
  
  -u -> A username
  
  -f -> Filename for a file containing a list of passwords
  
Example usage would look like this:

  ./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt
  
  ./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt
