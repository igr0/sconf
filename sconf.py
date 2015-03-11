#!/usr/bin/env python

import paramiko
import time
import getpass
import sys
import select
import re
import sys
import getopt
import socket

switch_report = ''
switches = [] 		#list to handle hostnames of switches
ssh = [] 			#list to handle ssh objects for each switch
info = []			#matrix that will contain all ports
batch_content = []	#same but for batch
force = False
ind_mode = ''
vlan_mode = ''
com_mode = ''

logging = '10.10.10.10'

switch_pairs = [
		['x','y'],
		['z1','z2']
		]

switch_map = {		#row to switch mapping (one switch of the pair can be entered)
		'p':'x',
		'ab':'z',
		}

### LOGGING ###
try:
	with open('/home/iosadchuk/test/sconf.log','a') as log:
		log.write(time.strftime("%c")+' '+getpass.getuser()+' '+' '.join(sys.argv)+"\n")
except:
	print "Please check permissions for log file"
###############

####################################################
#if __name__ == '__main__':

#print "\nPlease enter your username\n"
#username = raw_input('Username:')
username = 'user'
#print "\nPlease enter your password\n"
#password = getpass.getpass('Password:')
####################################################

def help():
	print "\nsconf.py is a python script for automated FEX ports configuration and VLAN provisioning on Nexus switches."
	print "\nThe following arguments can be used in command line:"
	print "\n  '-h' - Help"
	print "\n  '-p' - To provide list of ports for configuration in a command line instead of a file." 
	print "         The syntax is RACK_NUMBER,FEX_PORT,VLAN,DESCRIPTION"
	print "         Use ';' to separate individual ports in a list."
	print "         Note, that if you want to use spaces in your list, you have to enclose it with '',"
	print "         e.g. -p 'P1, 1, 501, SERIAL; P2, 15,[270,501-505],SERIAL'"
	print "\n  '-b' - Useful when list of ports is specfiied in a file instead of command line."
	print "         Path to the file with the list of ports has to follow."
	print "\n  '-y' - Use with CAUTION! Forces the script to push the config without asking for user confirmation."
	print "\n  '-i' - For an individual port configuration when you want to specify port during script execution."
	print "\n  '-v' - For the new VLAN provisioning on ALL Nexus switches at MDC."
	print "         The syntax is VLAN_ID,DESCRIPTION,MODE."
	print "         Mode can be 'fp' or 'ce' for FabricPath or ClassicEthernet respectively."
	print "\n  '-c' - This argument allows you to query all switches for specific 'show' command."
	print "\nExamples:"
	print "./sconf.py -p 'P1, 1, 501, SERIAL; P2, 15,[270,501-505],SERIAL'"
	print "./sconf.py -y -p 'P1, 1, 501, SERIAL; P2, 15,[270,501-505],SERIAL'"
	print "./sconf.py -b /path/to/file"
	print "./sconf.py -c 'show run vlan 200'"
	print "./sconf.py -i"
	print "./sconf.py -v 201,bbone,fp\n"

def SConf(command,push):
	global username
	global password
	global switch_report
	i = 3
	ssh = []
	
	switch_report += ', '.join(switches).upper()

	for switch in switches:
		while True:
			if i == 0:
				print "Could not connect to %s. Giving up." % switch
				sys.exit(1)	
#			print "Trying to connect to %s (%i/30)" % (switch, i)
			try:
				ssh_obj = paramiko.SSHClient()
				ssh_obj.set_missing_host_key_policy(paramiko.AutoAddPolicy())
				key = paramiko.RSAKey.from_private_key_file('/home/iosadchuk/tacacs.test_dir/id_rsa')
				ssh_obj.connect(switch, username=username, pkey=key, timeout = 300)
#				print "Connected to %s" % switch
				break
			except paramiko.AuthenticationException:
				print "Authentication failed when connecting to %s. You have %i attempts" % (switch,i)
				#print "\nPlease RE-enter your password\n"
				#password = getpass.getpass('Password:')
				i -= 1
				continue
			except paramiko.SSHException:
				print "SSH PROBLEM"
			except paramiko.ChannelException:
				print "CHANNEL PROBLEM"
			except paramiko.BadAuthenticationType:
				print "BAD AUTH"
			except:
				print "Could not SSH to %s, will try %i more times every 5 seconds" % (switch,i)
				i -= 1
				time.sleep(5)
		ssh.append(ssh_obj)		#building a list of opened ssh channels to each swtich
	
	if not push:	
		result = ''
		for switch,hostname in zip(ssh,switches):
			output = ''
			stdin, stdout, stderr = switch.exec_command(command)
			# Wait for the command to terminate
			while not stdout.channel.exit_status_ready():
				# Only print data if there is data to read in the channel
				if stdout.channel.recv_ready():
					output += stdout.channel.recv(8094)
				if stdout.channel.recv_stderr_ready():
					error += stdout.channel.recv_stderr(8094)
			exit_status = stdout.channel.recv_exit_status()
			
			result += "#"*5 + " " +  hostname.upper() + " " + "#"*5 + "\n"
			if output != '':
				result += output
			else:
				result += "Empty!\n"
#		print "_____________________________________________________\n"
		return result

	if push:
		    for switch in ssh:
				channel = switch.invoke_shell()
				
				stdin = channel.makefile('wb')
				stdout = channel.makefile('rb')

				stdin.write(command)
				stdin.write('end\nexit\n')

				print(stdout.read(8094))

				stdin.close()
				stdout.close()
				switch.close()

#Takes a list of ports and goes through configuration logic
def Process(info):
	global switches
	switches = []
	fex = ''
	switch_temp = ''
	if info:
		for entry in info:
			rack_num = entry[0]
			port = entry[1]
			vlan = entry[2]
			desc = entry[3]

			for rows in switch_map: 						#go through dictionary and check if we can find a row in a keys
				if rack_num[0].lower() in rows:				#
					switch_temp = switch_map[rows]			#If there is a match, assign $swtich_temp with a switch that serves this row
					for switch in switch_pairs:				#Go through list of switch pair and see which pair is the one that we need to configure
						if switch_temp in str(switch):
							switches = switch
							print "\n-------------------------------------------"
							print switches[0].upper() + " and " + switches[1].upper() + " WILL BE CONFIGURED."
							print "-------------------------------------------\n"
							break
					break
			if not switch_temp:
				print "Couldn't find a switch that serves row '"+rack_num[0]+"'. Check syntax for "+','.join(entry)
				sys.exit(1)

			show_fex = SConf("show fex",push=False)
			for line in show_fex.splitlines():
				if re.search(rack_num+'.+[OonlineNLINE]',line) and '#' not in line:
					fex = line.split()[0]
					break
			if not fex:
				print "Couldn't obtain FEX number. Please check your syntax for "+','.join(entry)
				exit()
			print "Please verify that fex number corresponds to the rack that you want to configure:"
			print SConf("show fex | inc "+fex,push=False)
			print "Interface status:"
			print SConf("show int status | inc '"+fex+"/1/"+port+" '",push=False)
			print "Port utilization:"
			print SConf("show int e"+fex+"/1/"+port+" | inc packets/sec",push=False)
			print "Following MAC addresses are connected to the port:"
			print SConf("show mac add int e"+fex+"/1/"+port+" | inc packets/sec",push=False)
			
			if not 'Trunk' in vlan:	
				print "The final configuration that is about to be pushed looks like:\n############################"
				config = '''configure terminal

interface e%s/1/%s
  description %s
  switchport mode access
  switchport access vlan %s
  spanning-tree port type edge
  no switchport trunk allowed vlan
  no shutdown\n''' % (fex,port,desc,vlan)
                		print config + "############################"
				if not force:   
					if Quest_bool():
						SConf(config,push=True)
						print (SConf("show run int e"+fex+"/1/"+port,push=False) if SConf("show run int e"+fex+"/1/"+port,push=False) else "None")
				if force:
					SConf(config,push=True)
					print SConf("show run int e"+fex+"/1/"+port,push=False)
            
			if ('Trunk' in vlan):
				vlan = vlan[5:]
				print "The final configuration that is about to be pushed looks like:\n############################"

				config = '''configure terminal

interface e%s/1/%s
  description %s
  switchport mode trunk
  no switchport access vlan
  switchport trunk allowed vlan %s
  spanning-tree port type edge trunk
  no shutdown\n''' % (fex,port,desc,vlan)
				print config + "############################"
				if not force:	
					if Quest_bool():
						SConf(config,push=True)
						print SConf("show run int e"+fex+"/1/"+port,push=False)
				if force:
					SConf(config,push=True)
					print SConf("show run int e"+fex+"/1/"+port,push=False)
			fex = ''
			port = ''
			vlan = ''
			desc = ''
			rack_num = ''

def Syntax_check(port):
	if len(port) != 4:
		print "Each port must consist of exactly 4 parts: RACK_#,FEX_PORT,VLAN,DESCRIPTION. Is it the case for:'"+','.join(port)+"'?"
		exit()
	if not re.search('^[A-Za-z]..?$',port[0]): #check rack number syntax
		print "In a port '"+','.join(port)+"' rack "+port[0]+" looks wrong."
		exit()
	if not re.search('^([1-9]|([1-3][0-9])|(4[0-8]))$',port[1]): #check if port number was entered correctly, e.g. 1-32
		print "Port numbers must be in a range between 1 and 48. '"+port[1]+"' in "+','.join(port)+" doesn't look valid."
		exit()
	if not re.search('(^\d+$)|(^\d+((-|,)\d+)+$)',port[2]):
		print "VLAN must be a number. It is something else in "+','.join(port)
		exit()
	if len(port[3]) > 80:
		print "Maximum number of symbols for port description is 80. Yours is too long in '"+','.join(port)+"'"
		exit()

def Vlan_config(string):
	global switches
	vlan_info = string.split(',')
	
	if len(vlan_info) != 3:
		print "VLAN definition must consist of 3 fields: VLAN_ID,DESCRIPTION,MODE"
		exit()
	
	try:
		vlan = str(int(vlan_info[0]))
	except ValueError:
		print "VLAN ID must be a number. Try one more time."
		exit()
	
	if len(vlan_info[1]) < 80:
		desc = vlan_info[1].upper()
	else:
		print "Maximum number of symbols for port description is 80. Yours is too long"
		exit()
	
	if re.search("(^\s*fp\s*$)|(^\s*ce\s*$)",vlan_info[2].lower()):
		if 'fp' in vlan_info[2].lower():
			mode = 'fabricpath'
		else:
			mode = 'ce'
	else:
		print "Please enter valid VLAN mode ('fp' for FabricPath or 'ce' for ClassicEthernet)."
		exit()

	for entry in switch_pairs:
		for switch in entry:
			switches.append(switch)
	print "\nConfig will be pushed to the following switches:"
	for switch in switches:
		print switch.upper()
	
	print "\nThe final configuration that is about to be pushed looks like:\n############################"
	config = "configure terminal\n\nvlan "+vlan+"\nname "+desc+"\nmode "+mode+"\n"
	print config + "############################"

	if not force:
		if Quest_bool():
			SConf(config,push=True)
			print SConf("show run vlan "+vlan,push=False)

	if force:
		SConf(config,push=True)
		print SConf("show run vlan "+vlan,push=False)

def Str2list(string):
	if '[' in string and ']' in string:    #check if trunk ports have to be configured. 
		temp_vlan = string[string.find('[')+1:string.find(']')]
		string_mod = string[0:string.find('[')]+'X'+string[string.find(']')+1:len(string)]
		new_list = string_mod.replace('\t','').replace(' ','').upper().split(',')
		try:
			if new_list[2] == 'X':
				new_list[2] = temp_vlan
			else:
				print "Please check syntax for port: '"+string+"'"
				exit()
		except IndexError:
			print "Please check syntax for port: '"+string+"'"
			exit()
		return new_list
	new_list = string.replace('\t','').replace(' ','').upper().split(',')
	return new_list

def Quest_bool():
	while True:
		answer = raw_input("Do you want to proceed with this configuration? 'y/[N]' ('q' to exit): ") or 'n'
		if re.search('^(n|N)$',answer):
			return False
			break
		elif re.search('^(y|Y)$',answer):
			return True
			break
		elif re.search('^(q|Q)$',answer):
			print "Exiting..."
			sys.exit()
		else:
			print "Please answer with 'y/Y/n/N'."


###############################################
try:	#catching interrupt signal
	
	if len(sys.argv) > 1:
		
		try:
			opts,args = getopt.getopt(sys.argv[1:],"c:hyiv:b:p:") #defining how arguments must look like
		except:
			print 'Something is wrong with your arguments. Please reference help.'
			help()
			exit()

		for arg in sys.argv:	# check if configuraiton should be done without confirmation
			if arg == '-y':
				force = True
			if arg == '-i':
				ind_mode = True
			#see comment where vlan_mode block is defined
			#if arg == '-v':
			#	vlan_mode = True
			if arg == '-c':
				com_mode = True
				for arg in range(0, len(sys.argv)):	
					if '-c' in sys.argv[arg]:
						try:
							#for now interactive mode is disabled on arguments check phase.
							#However logic for it is here. Just change arguments requirements to enable it. 
							#Else statement is always hit now.
							if '-' in sys.argv[arg+1]:
								inter = True
							else:
								if re.search('^\s*show.+',sys.argv[arg+1].lower()):
									com = sys.argv[arg+1].lower()
								else:
									print "What you entered, doesn't look like a 'show' command. Try again."
									exit()
								inter = False
						except ValueError:
							inter = True

		for opt,arg in opts:
			
			if opt in ("-h"):
				help()
				exit()
			
			if opt in ('-v'):
				Vlan_config(arg)
			
			if opt in ("-p"):
				temp = arg	#list of ports that passed as an argument
				if ';' in str(temp):				#check if multiple ports were specified
					ind_ports = temp.split(';')		#list containing all individual ports
					for port in ind_ports:
						port = Str2list(port)
						Syntax_check(port)	
						if ',' in port[2] or '-' in port[2]:
							port[2] = 'Trunk' + port[2]
						#essentially creates a matrix with individual ports and their attributes
						info.append(port)
				#if only one port was specified, then just create a list from argument
				else:
						port = Str2list(temp)
						Syntax_check(port)
						if ',' in port[2] or '-' in port[2]:
							port[2] = 'Trunk' + port[2]
						info.append(port) 
				Process(info)
				info = []
				port = []

			#batch mode was passed as an argument
			if opt in ('-b'):
				batch_content = []
				path = arg	#path to the file with the list of ports should be an argument of -b
				try:
					with open(path) as f:
						content = f.readlines()
					for line in content:
						if not re.search("^(\B|#)",line):
							if re.search('\n$',line):
								port = Str2list(line[0:len(line)-1])
							else:
								port = Str2list(line)
							Syntax_check(port)
							batch_content.append(port)
					content = ''
				except IOError:
					print "Wrong path was specified. Check your syntax."
					exit()
				
				if batch_content:
					for port in batch_content:
						if ',' in port[2] or '-' in port[2]:
							port[2] = 'Trunk'+port[2]
						info.append(port)
				else:
					print "File contains errors. Please check it."
					exit()
				Process(info)
				info = []
				port = []

	else:
		help()
		exit()

	#if -i was selected, bring up dialog
	if ind_mode:
		
		print "\nPlease enter the switch pair that you want to configure\n"
		switches = raw_input('Hostnames (comma separated):').replace(' ',"").split(',')  #build a list of hostnames that were entered
		if len(switches) < 2:
			print "\nOnly one switch was entered. Check your syntax, dude.\n"
			exit()
		elif len(switches) > 2:
			print "\nWay too many switches. I asked for two only. Check your syntax and start over.\n"
			exit()
		
		print "\n"+"#"*13+" THE FOLLOWING FEX'ES ARE CONNECTED TO THIS PAIR " +"#"*13+"\n"
		print SConf("show fex",push=False)
		while True:
			try:
				fex = int(raw_input("Please choose the FEX number from the above table(e.g. 101): "))
				fex = str(fex)
				break
			except ValueError:
				print "We asked for number but letter was detected. Try one more time.\n"

		print "\nPorts connected to this FEX have the following configuration:\n"
		print SConf("show int status | inc "+fex+"/1",push=False)

		while True:
			try:
				port = int(raw_input("Please select the port you want to configure(e.g. 5): ")) 
				port = str(port)
				break
			except ValueError:
				print "Value cannot contain letters. Try one more time.\n"

		print "Running configuration:"
		print SConf("show run int e"+fex+"/1/"+port,push=False)
		print "Port utilization:"
		print SConf("show int e"+fex+"/1/"+port+" | inc packets/sec",push=False)
		print "Following MAC addresses are connected to the port:"
		print SConf("show mac add int e"+fex+"/1/"+port+" | inc packets/sec",push=False)
		
		while True:
			mode = raw_input("\nDo you want to configure this port as access or trunk? Options: 'access/trunk/[A]/t' or 'q' to exit: ") or 'A'
			access = ['A','a','access']
			trunk = ['T','t','trunk']
			if mode in access:
				mode = 'access'
				break
			elif mode in trunk:
				mode = 'trunk'
				break
			elif mode == 'q':
				exit()	
			else:
				print "Wrong value! Please use any of these: 'access/trunk/[A]/t' or 'q' to exit"

		if mode == 'access':
			while True:
				try:
					vlan = int(raw_input("\nAccess port was selected. Please enter VLAN ID for this port(e.g. 201): "))
					vlan = str(vlan)
					break
				except ValueError:
					print "We asked for number but letter was detected. Try one more time.\n"
			desc = raw_input("\nPlease enter port description (usually serial number of the server): ").upper()
			print "\n\n\n\n\nThe final configuration that is about to be pushed looks like:\n############################"
			config = "configure terminal\n\ninterface e"+fex+"/1/"+port+"\n\ndescription "+desc+"\nswitchport mode access\nswitchport access vlan "+vlan+"\nspanning-tree port type edge\nno switchport trunk allowed vlan\nno shutdown\n"
			print config + "############################"
			answer = Quest_bool() 
			if answer:
				SConf(config,push=True)
				print SConf("show run int e"+fex+"/1/"+port,push=False)
		if mode == 'trunk':
			while True:
				try:
					vlans = raw_input("\nTrunk port was selected. Please enter all VLAN ID's that must be allowed on the port(e.g. 1,2,3,4-8): ").replace(' ','')
					vlans_list = vlans.split(',')
					#for vlan in vlans_list:
					#	vlan = int(vlan)		#test if all values that were entered are numbers
					vlans = str(vlans)
					break
				except ValueError:
					print "Atleast one of the values doesn't seem to be a VLAN ID. Try one more time.\n"
			desc = raw_input("\nPlease enter port description (usually serial number of the server): ").upper()
			print "\n\n\n\n\nThe final configuration that is about to be pushed looks like:\n############################"
			config = "configure terminal\n\ninterface e"+fex+"/1/"+port+"\n\ndescription "+desc+"\nswitchport mode trunk\nno switchport access vlan\nswitchport trunk allowed vlan "+vlans+"\nspanning-tree port type edge trunk\nno shutdown\n"
			print config + "############################"
			answer = Quest_bool()
			if answer:
				SConf(config,push=True)
				print SConf("show run int e"+fex+"/1/"+port,push=False)
	
	'''
	#Interactive mode is disabled unless someone ask for it
	if vlan_mode:
		switches = []
		for entry in switch_pairs:
			for switch in entry:
				switches.append(switch)
		print "\nConfig will be pushed to the following switches:"
		for switch in switches:
			print switch.upper()
		while True:
			try:
				vlan =str(int(raw_input("Please enter VLAN ID to be pushed to all switches listed above(e.g. 201): ")))
				break
			except ValueError:
				print "\nWe asked for number but letter was detected. Try one more time."

		name = raw_input("Please enter VLAN description: ").upper()
		while True:
			mode = raw_input("Please enter VLAN mode '[Fabricpath]/CE': ").lower() or "fabricpath"
			if mode == 'fabricpath' or mode == 'ce':
				break
			else:
				print "\nPlease specify proper VLAN mode. Or just hit Enter to select Fabricpath."

		print "\n\n\n\n\nThe final configuration that is about to be pushed looks like:\n############################"
		config = "configure terminal\n\nvlan "+vlan+"\nname "+name+"\nmode "+mode+"\n"
		print config + "############################"
		
		answer = Quest_bool()
		if answer:
			SConf(config,push=True)
			print SConf("show run vlan "+vlan,push=False)
	'''

	if com_mode:
		switches = []
		for entry in switch_pairs:
			for switch in entry:
				switches.append(switch)
		print "\nThe following switches will be polled:"
		for switch in switches:
			print switch.upper()
		if inter:	
			while True:
				com = raw_input("Please enter 'show' command: ").lower()
				if re.search('^\s*show.+',com):
					break
				else:
					print "What you entered, doesn't look like a 'show' command. Try again."
		print "############################"
		print com
		print "############################"

		if not force:
			if Quest_bool():
				print SConf(com,push=False)
		if force:
			print SConf(com,push=False)

except KeyboardInterrupt:
	print "\nInterrupt got caught! Exiting gracefully..."


FACILITY = {
	'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
	'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
	'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
	'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
	'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
	'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
	'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

def syslog(message, level=LEVEL['notice'], facility=FACILITY['local7'],host=logging,port=514):
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = '<%d>%s' % (level + facility*8, message)        
	sock.sendto(data, (host, port))
	sock.close()

syslog('sconf logged in to ' + switch_report)
