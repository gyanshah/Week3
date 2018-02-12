    ############# Application #3 - Part #1 #############

#DHCP client simulator


import subprocess
import logging
import random
import sys


#This will suppress all messages that have a lower level of seriousness than error messages, while running or loading Scapy
"""logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)"""


try:
    from scapy.all import *

except ImportError:
    print ("Scapy package for Python is not installed on your system.")
    print ("Get it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()
    


#To see a list of what commands Scapy has available, run the lsc() function.
#Run the ls() command to see ALL the supported protocols.
#Run the ls(protocol) command to see the fields and default values for any protocol.
#See packet layers with the .summary() function.
#See packet contents with the .show() function.
#Dig into a specific packet layer using a list index: pkts[3][2].summary()...
#...the first index chooses the packet out of the pkts list, the second index chooses the layer for that specific packet.
#Using the .command() packet method will return a string of the command necessary to recreate that sniffed packet.



print ("\n! Make sure to run this program as ROOT !\n")

#Setting network interface in promiscuous mode
net_iface = input("Enter the interface to the target network: ")

"""subprocess.call(["ifconfig", net_iface, "promisc"], stdout=None, stderr=None, shell=False)

print ("\nInterface %s was set to PROMISC mode." % net_iface)
"""


#Scapy normally makes sure that replies come from the same IP address the stimulus was sent to.
#But our DHCP packet is sent to the IP broadcast address (255.255.255.255) and any answer packet will have the IP address of the replying DHCP server as its source IP address (e.g. 192.168.2.101).
#Because these IP addresses don't match, we have to disable Scapy's check with conf.checkIPaddr = False before sending the stimulus.
#Source: https://bitbucket.org/pbi/test/wiki/doc/IdentifyingRogueDHCPServers
conf.checkIPaddr = False


    ############# Application #3 - Part #2 #############


################## DHCP SEQUENCE #################
all_given_leases = []
server_id = []
client_mac = []

#Generate entire DHCP sequence
def generate_dhcp_seq():
    global all_given_leases
    
    #Defining some DHCP parameters
    x_id = random.randrange(1, 1000000)
    hw = "00:00:5e" + str(RandMAC())[8:]
    hw_str = mac2str(hw)
    #print hw
    
    #Assigning the .command() output of a captured DHCP DISCOVER packet to a variable
    dhcp_dis_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=hw_str)/DHCP(options=[("message-type","discover"),("end")])
    
    #Sending the DISCOVER packet and catching the OFFER reply
    #Generates two lists (answ and unansw). answd is a list containg a tuple: the first element is the DISCOVER packet, the second is the OFFER packet
    answd, unanswd = srp(dhcp_dis_pkt, iface=pkt_inf, timeout = 2.5, verbose=0)
    
    #print answd
    #print unanswd
    #print answd.summary()
    #print unanswd.summary()
    #print answd[0][1][BOOTP].yiaddr
    
    #The IP offered by the DHCP server to the client is extracted from the received answer
    offered_ip = answd[0][1][BOOTP].yiaddr
    #print offered_ip
    
    #Assigning the .command() output of a captured DHCP REQUEST packet to a variable
    dhcp_req_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=hw)/IP(src="0.0.0.0",dst="255.255.255.255") / UDP(sport=68,dport=67)/BOOTP(op=1, xid=x_id, chaddr=hw_str)/DHCP(options=[("message-type","request"),("requested_addr", offered_ip),("end")])
    
    #Sending the REQUEST for the offered IP address
    #Capturing the ACK from the server
    answr, unanswr = srp(dhcp_req_pkt, iface=pkt_inf, timeout = 2.5, verbose=0)   
    
    #print answr
    #print unanswr
    #print answr[0][1][IP].src
    #print answr[0][1][BOOTP].yiaddr
    
    #The IP offered by the DHCP server to the client is extracted from the received answer
    offered_ip_ack = answr[0][1][BOOTP].yiaddr
    
    #DHCP Server IP/ID
    server_ip = answr[0][1][IP].src
    #print server_ip
    
    #Adding each leased IP to the list of leases
    all_given_leases.append(offered_ip_ack)

    #Adding the server IP to a list
    server_id.append(server_ip)

    client_mac.append(hw)    
    
    return all_given_leases, server_id, client_mac


    ############# Application #3 - Part #4 #############


################## USER MENU #################
try:
    #Enter option for the first screen
    while True:
        print ("\nUse this tool to:\ns - Simulate DHCP Clients\nr - Simulate DHCP Release\ne - Exit program\n")
        
        user_option_sim = input("Enter your choice: ")
        
        if user_option_sim == "s":
            print ("\nObtained leases will be exported to 'DHCP_Leases.txt'!")
            
            pkt_no = input("\nNumber of DHCP clients to simulate: ")
            
            pkt_inf = input("Interface on which to send packets: ")
            
            print ("\nWaiting for clients to obtain IP addresses...\n")
            
            try:
                #Calling the function for the required number of times (pkt_no)
                for iterate in range(0, int(pkt_no)):
                    all_leased_ips = generate_dhcp_seq()[0]
                      
                #print all_leased_ips
                
            except IndexError:
                print ("No DHCP Server detected or connection is broken.")
                print ("Check your network settings and try again.\n")
                sys.exit()
                
            #List of all leased IPs
            dhcp_leases = open("DHCP_Leases.txt", "w")
            
            #print all_leased_ips
            #print server_id
            #print client_mac
            
            #Print each leased IP to the file
            for index, each_ip in enumerate(all_leased_ips):
                
                print(dhcp_leases, each_ip + "," + server_id[index] + "," + client_mac[index])
                
            dhcp_leases.close()
            
            continue

            
        else:
            print ("Exiting... See ya...\n\n")
            sys.exit()

except KeyboardInterrupt:
    print ("\n\nProgram aborted by user. Exiting...\n")
    sys.exit()            

#End of program
