# My-Ping
The file MyPing.c is about creating an icmp request (like ping) and sending it to some ip (int this case 8.8.8.8) using raw socket.  
The file ICMP_Sniffer.c is about sniffing icmp packets and printing their information (source ip, destination ip, type and code).  
If you run the ICMP_Sniffer.c file and then run MyPing.c you should see the details of the packet created in MyPing.c printed on the screen.
