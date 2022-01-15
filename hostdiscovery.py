import nmap
import sys
import time




def fun(str):
    nm_scan = nmap.PortScanner()
    print("\nRunning.....\n")
    nm_scanner = nm_scan.scan(sys.argv[1], '80', str)
    host_is_up = "The host is: " + nm_scanner['scan'][sys.argv[1]]['status']['state'] + ".\n"
    port_open = "The port 80 is: " + nm_scanner['scan'][sys.argv[1]]['tcp'][80]['state'] + "\n"
    method_of_scanning = "The method of scanning is: " + nm_scanner['scan'][sys.argv[1]]['tcp'][80]['reason'] + "\n"
    service_name = "The service used is: " + nm_scanner['scan'][sys.argv[1]]['tcp'][80]['name']

    print(host_is_up)
    print(port_open)
    print(method_of_scanning)
    print(service_name)

    with open("%s.txt" % sys.argv[1], 'w') as f:
        f.write(host_is_up + port_open + method_of_scanning + service_name)
        f.write("\nReport generated " + time.strftime("%Y-%m-%d_%H:%M:%S GMT", time.gmtime()))
        print("\nFinished.......")



while(True):
    print("""
    NMAP Advanced Scan Method	NMAP Advanced Scan Flag
    1.TCP SYN Scan	                  -sS
    2.TCP Connect Scan	              -sT
    3.TCP FIN Scan	                  -sF
    4.TCP NULL Scan	                  -sN
    5.TCP ACK Scan	                  -sA
    6.Custom TCP Scan	              –scanflags
    7.UDP Scan	                      -sU
    8.Xmas Scan	                      -sX
   """)

    inp=int(input("Enter which scan you want e.g 4\n\n"))

    if inp == 1:

        fun("-sS")
        break

    if inp == 2:
        fun("-sT")
        break

    if inp == 3:
        fun("-sF")
        break

    if inp ==4:
        fun("-sN")
        break

    if inp==5:
        fun("-sA")
        break

    if inp==6:
        fun("–scanflags")
        break

    if inp==7:
        nm_scan = nmap.PortScanner()
        print("\nRunning.....\n")
        nm_scanner = nm_scan.scan(sys.argv[1], '80', '-sU')
        host_is_up = "The host is: " + nm_scanner['scan'][sys.argv[1]]['status']['state'] + ".\n"
        port_open = "The port 80 is: " + nm_scanner['scan'][sys.argv[1]]['udp'][80]['state'] + "\n"
        method_of_scanning = "The method of scanning is: " + nm_scanner['scan'][sys.argv[1]]['udp'][80]['reason'] + "\n"
        service_name = "The service used is: " + nm_scanner['scan'][sys.argv[1]]['udp'][80]['name']

        print(host_is_up)
        print(port_open)
        print(method_of_scanning)
        print(service_name)

        with open("%s.txt" % sys.argv[1], 'w') as f:
            f.write(host_is_up + port_open + method_of_scanning + service_name)
            f.write("\nReport generated " + time.strftime("%Y-%m-%d_%H:%M:%S GMT", time.gmtime()))
            print("\nFinished.......")

        break

    if inp ==8:
        fun("-sX")
        break



















# nm_scan=nmap.PortScanner()
# print("\nRunning.....\n")
#
# nm_scanner=nm_scan.scan(sys.argv[1],'80','-sT')
# # nm_scanner=nm_scan.scan(sys.argv[1],'80',arguments='-O')
#
# host_is_up="The host is: "+ nm_scanner['scan'][sys.argv[1]]['status']['state'] +".\n"
# port_open="The port 80 is: "+nm_scanner['scan'][sys.argv[1]]['tcp'][80]['state']+"\n"
# method_of_scanning="The method of scanning is: "+nm_scanner['scan'][sys.argv[1]]['tcp'][80]['reason']+"\n"
# # guessed_os="There is is %s percent chance that the host is running %s "%(nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['accuracy'],nm_scanner['scan'][sys.argv[1]]['osmatch'][0]['name'])+".\n"
#
#
# with open("%s.txt"%sys.argv[1],'w') as f:
#     f.write(host_is_up+port_open+method_of_scanning)
#     f.write("\nReport generated "+time.strftime("%Y-%m-%d_%H:%M:%S GMT",time.gmtime()))
#
#
# print("\nFinished.......")


# print("The host is : "+nm_scanner['scan']['172.217.20.14']['status']['state'])
# print("The Scanning method  is : "+nm_scanner['scan']['172.217.20.14']['tcp'][80]['reason'])
# print("There is %s percent chance that the host running is %s "%(nm_scanner['scan']['172.217.20.14']['osmatch'][0]['accuracy'],nm_scanner['scan']['172.217.20.14']['osmatch'][0]['name']))



