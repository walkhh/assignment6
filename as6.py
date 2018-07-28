# from py 3.6 std library
# https://docs.python.org/3/library/socket.html#example
import socket
# https://docs.python.org/3/library/ipaddress.html
import ipaddress
import subprocess
import re
import os
import platform


# Used to validate the format of IPv4 addresses
def isIPv4(str):
	pattern = r'([0-9]{1,3}\.){3}[0-9]{1,3}'
	return re.match(pattern, str)

# Used to validate the format of IPv6 addresses
def isIPv6(str):
	pattern = r'(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}'
	return re.match(pattern, str)

# Used to validate the format of fully qualified domain names
def isFQDN(str):
	pattern = r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}'
	return re.match(pattern, str)

# Retrieves the information pertaining to the subnet mask of the user's network
def get_mask():
	# Used to confirm the validity of an ipaddress; See documentation on regex (regular expression)
	ipstr = '([0-9]{1,3}\.){3}[0-9]{1,3}'

	# Retrieve the name of the host operating system 
	if os.name == 'nt':  # windows system
		ipconfig = subprocess.Popen("ipconfig", stdout=subprocess.PIPE)
		mask_pattern = re.compile(r"Subnet Mask (\. )*: %s" % ipstr)
	else:  # linux
		ipconfig = subprocess.Popen("ifconfig", stdout=subprocess.PIPE)
		mask_pattern = re.compile("netmask %s" % ipstr)

	output = ipconfig.stdout.read() # output of the terminal/cmd in bytes 
	pattern = re.compile(ipstr)
	masklist = []

	#extract the masks from the output
	for maskaddr in mask_pattern.finditer(str(output)):
		mask = pattern.search(maskaddr.group())
		masklist.append(mask.group())

	return masklist

# Retrieves the information about the host network
def showInfo():
	host_name = socket.gethostname()
	print("Your Hostname is: \n\t" + host_name)
	host_ipv4 = socket.gethostbyname(host_name)
	print("Your IP Address (ipv4): \n\t" + host_ipv4)
	addr_data_list = socket.getaddrinfo(host_name, 80, socket.AF_INET6)
	print("Your IP Addresses (ipv6): ", end="")
	for addr_data in addr_data_list:
		print("\n\t"+addr_data[4][0], end="")
	mask = get_mask()
	print("\nSubnet mask(s):\n", end="")
	for netmask in mask:
		print("\t"+str(netmask))
	

# Retrieves the IP address from the fully qualified domain name
def fqdnToIp():
	uFQDN = input("Enter a fully qualified domain name (FQDN): ")
	if not isFQDN(uFQDN):
		print("Not a FQDN!")
		return
	print("The FQDN you entered was ", uFQDN)
	print("the IP address of ", uFQDN, ": ", socket.gethostbyname(uFQDN))

# Retrieves the fully qualified domain name for the given ipaddress
def ipToFqdn():
	ipAddr = input("Enter an IP address: ")
	if isIPv4(ipAddr):
		print("You entered an Ipv4 address.")
	elif isIPv6(ipAddr):
		print("You entered an Ipv6 address.")
	else:
		print("Not an IP address!")
		return
	FQDN = socket.getfqdn(ipAddr)
	print("The FQDN is: " + FQDN)

# Executes the ping command via terminal/cmd; 
# prompting the user for the ping target and number of packets they wish to send 
def doPing():
	name = input("Enter a hostname or IP address: ")
	if isIPv4(name):
		print("You entered an Ipv4 address.")
	elif isIPv6(name):
		print("You entered an Ipv6 address.")
	elif isFQDN(name):
		print("You entered a FQDN.")
	else:
		print("Invalid ping target!")
		return

	packets = input("Enter the number of packets you wish to send: ")
	# str -> int will throw an error if containing non numbers
	try:
		int(packets) 
	except ValueError:
		print("Invalid number of packets!")

	
	if os.name == 'nt':  # windows system
		print(os.system("ping -n " + packets + " " + name))
	else: # linux distro
		print(os.system("ping -c " + packets + " " + name))

# Executes traceroute command via terminal/cmd
def doTraceRoute():
	name = input("Enter a hostname or IP address: ")
	if isIPv4(name):
		print("You entered an Ipv4 address.")
	elif isIPv6(name):
		print("You entered an Ipv6 address.")
	elif isFQDN(name):
		print("You entered a FQDN.")
	else:
		print("Invalid traceroute target!")
		return

	if os.name == 'nt':  # windows system
		print(os.system("tracert " + name))
	else:
		print(os.system("traceroute " + name))
		
def doServiceTest():
	name = input("Enter a hostname or IP address: ")
	if isIPv4(name):
		print("You entered an Ipv4 address.")
	elif isIPv6(name):
		print("You entered an Ipv6 address.")
	elif isFQDN(name):
		print("You entered a FQDN.")
	else:
		print("Invalid target!")
		return
		
	dict = {}
	dict["SMTP"] = [25, 587, 465]
	dict["SSH"] = [22]
	dict["HTTP"] = [80]
	dict["HTTPS"] = [443]
	dict["SNMP"] = [161, 162]
	dict["DNS"] = [53]
	dict["FTP"] = [20, 21]
	dict["LDAP"] = [389]
	dict["RPC"] = [135]

	service = input("Enter the service to test: ").upper()

	for port in dict[service]:	
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		result = sock.connect_ex((name, port))
		if result == 0:
			print("The service", service, "on port", port, "is available")
		else:
			print("The service", service, "on port", port, "is NOT available (code", str(result) + ")")

		

# The main method containing the shell ui
def __main__():
	# Identify the host os
	print("\nNote: This program supports Linux and Windows.\nCurrent host OS: " +
			str(platform.system()))
	# Assuming linux if not windows
	if os.name != 'nt': 
		print("\nSince you're not running windows 'traceroute' and 'ifconfig' are required " +
			"for execution of this program.\nTo do this, run the commands: "+
			"'sudo apt install net-tools' and 'sudo apt install traceroute' in your terminal.\n")

	# Begin program execution
	while True:
		print("\n\t" + "0. Exit")
		print("\t" + "1. Show machine's IPv4, IPv6, and subnet information.")
		print("\t" + "2. Get an IP from a FQDN")
		print("\t" + "3. Get a FQDN from an IP")
		print("\t" + "4. Ping a server")
		print("\t" + "5. Trace route to target")
		print("\t" + "6. Test services on server")
		num = input("Please enter a command number: ")
		print("\n")

		if num == "0":
			print("Goodbye. The results can now be copied to a text editor and printed.")
			quit()
		elif num == "1":
			showInfo()
		elif num == "2":
			fqdnToIp()
		elif num == "3":
			ipToFqdn()
		elif num == "4":
			doPing()
		elif num == "5":
			doTraceRoute()
		elif num == "6":
			doServiceTest()
		else:
			print("Invalid option.")


__main__()
