#!/bin/perl

#################################################################################################
# ARP Scan											#
# by RootSecks											#
#												#
# 												#
# Spams the network with ARP Requests and looks for replys, reply means existing hosts		#
#################################################################################################

use strict; #Use Strict because my coding style could be described as a "Disaster" and strict will catch some of the mistakes
use Net::Write::Layer2; #Use Net::Write::Layer2 to craft ARP Packets
use Net::Pcap qw( :functions ); #Use Net::Pcap to capture incoming packets
use threads; #Use threads so we can create a new thread for the pcap loop
use threads::shared; #Use this so we can share variables between threads
use IO::Socket::INET; #Get some Socket action up in this biaotch

#Grab the interface from the cmd line
my $ethinterface = shift;
#If none specified
if ($ethinterface == 0) {
	#Default to eth0
	$ethinterface = 'eth0';
}

#Get a the mac address of the chosen interface
my ($mac, $ipaddress, $ipsubnet)  = &get_interface_information($ethinterface);

#initaliez dispatch int for stuff
our $dispatch :shared;
$dispatch = 0;

#Global to hold found hosts
my @foundhosts :shared;

#Array to hold common TCP Ports
my @tcpcommonports :shared = (20, 22, 23, 25, 80, 443, 445, 3389, 5900, 8008, 8080);

#ARP Scan
&arp_scan;

for (my $g = 0; $g <= $#foundhosts; $g++) {
	
	print "$foundhosts[$g]\n";
	
}



#Sub to contain the ARP scan
sub arp_scan {
	

	#Convert the src ip address to hex so we can pack it into the frames
	my $srcipaddress = &get_hex_of_ip($ipaddress, 1);


	#Get the network bits and the empty host bits and the legnth of the host bits from the ip address
	my ($networkbits, $binaryhostbits, $hostlength) = &get_networkbits_from_ip($ipaddress, $ipsubnet);


	#Initalize ethernet device
	my $ethherp = Net::Write::Layer2->new(dev => $ethinterface);

	#Create a thread to handle capturing the returning packed. Since I'm using Net::Write instead of Net::Frame, I can't just use Net::Frame::Online easily
	my $pcapthread = threads->create(\&packetcapture);

	#Sleep a bit to let the thread get all up and running before we start sending out ARP Requests
	sleep(1);

	#My Hostbits, starting with 1
	my $hostbits = 1;

	#We calculate the maximum decimal possible based on the length of the host portion of the ip address ((2^length)-1) and we loop until we hit that
	while ($hostbits <= ((2 ** $hostlength)-1)) {
		
		#We take the host bits decimla and convert into binary
		my $binaryhost = sprintf('%.*b',$hostlength, $hostbits);
		
		#####################BUILDING THE ETHERNET FRAME####################################
		#There would usually be a preample here, since it's conceptually part of the layer 2 header, but as part of this module. the preamble is done 
		#Also, the FCS (Frame Check Sequence, CRC) is also done so whatevs
		my $destmac = pack("B48", sprintf('%.48b', 0xffffffffffff)); #Destination MAC Address all 1s as a layer 2 broadcast
		my $srcmac = pack("B48", sprintf('%.48b', hex $mac));
		my $ethtype = pack('B16', sprintf('%.16b', 0x0806)); #Ethertype, in this case it's ARP
		####################################################################################

		################BUILDING THE ARP PACKET#############################################
		my $hardwaretype = pack('B16', sprintf('%.16b', 1)); #Layer 2 type, in this case, ethernet
		my $prototype = pack('B16', sprintf('%.16b', 0x0800)); #Layer 3 type, in this case it's IPv4
		my $hardwareaddrlength = pack('B8', sprintf('%.8b', 6)); #This is the length of the layer 2 address, 48 bits for a MAC Address
		my $protocoladdrlength = pack('B8', sprintf('%.8b', 4)); #This is the length of the layer 3 address, 32 bits for an IPv4 Address
		my $operation = pack('B16', sprintf('%.16b', 1)); #This is the ARP Operation, 1 for request, 2 for reply. There are others, like 4 for reverse reply but thats out of scope
		my $senderhardwareaddress = pack('B48', sprintf('%.48b', hex $mac)); #This is the MAC Address of the sender.
		my $senderprotocoladdressaddress = $srcipaddress;#This is teh IP of the sender
		my $targethardwareaddress = pack('B48', sprintf('%.48b', 0xffffffffffff)); #This is MAC of the dest, rfc says it's ignored in a request
		my $targetprotocoladdressaddress  = pack('B32', "$networkbits$binaryhost"); #This is the IP of the dest, ie the host we want a MAC for
		####################################################################################

		#Put the ARP Packet together
		my $arpheader = "$hardwaretype$prototype$hardwareaddrlength$protocoladdrlength$operation$senderhardwareaddress$senderprotocoladdressaddress$targethardwareaddress$targetprotocoladdressaddress";

		#Put the ethernet frame together
		my $ethheader = "$destmac$srcmac$ethtype";

		#Encapsulate the ARP packet in the ethernet frame (I say encapsulate, it's really just a concaternation since the FCS is done later lol)
		my $etherframe = "$ethheader$arpheader";

		#Open the connection
		$ethherp->open;
		
		#Send the frame
		$ethherp->send($etherframe);
		
		#Close that shit
		$ethherp->close;

		#Increment the hostbits
		$hostbits ++;

	}



	#Dispach complete
	$dispatch = 1;

	#Rejoin thread
	$pcapthread->join();

}



#Sub for capturing packets
sub packetcapture {

	#Initalize the error variabe
	my $err = '';

	#Open for listening
	my  $pcap = pcap_open_live('eth0', 1024, 1, 0, \$err);

	#Announce we're capturing
	#print "We're shaking the tree, lets see what falls out ^___^\n";

	#While dispatch hasn't finished
	until ($dispatch == 1) {

		#Loop through 1 packet
		pcap_loop($pcap, 1, \&process_packet, "Gettin my derp on");
		
	}
	
	#Finished!
	#print "Work Complete :D\n";

}




#Sub for processing the captured packet
sub process_packet {
	
	#Get the data inputed
	my($user_data, $header, $packet) = @_;
	
	#Lengh of the packet
	my $len = length($packet);
	
	#Counter for length 
	my $i = 0;
	
	#Variable to hold bits of packets
	my $lg;
	
	#How far to cut
	my $cutlength;
	
	#The unpacked hex
	my $ethertypeunpack;
	
	my @iparray;
	
	#Variable to see if we care about this frame
	my $packetpickup = 0;
	
	
	#Until we hit the end of the frame
	until ($i >= $len) {
		
		#If we are less than 6 bytes into the frame (Dest Mac Feild)
		if ($i < 6) {
					
			#Define the cut length of 6 bytes
			$cutlength = 6;
			
			#We cut off the fronf of the frame (The dest mac feild)
			$lg = substr($packet, $i, $cutlength);
			
			#Increment length counter
			$i += 6;
			
			#Populate the hex unpacked into a var
			$ethertypeunpack = unpack ('H12', $lg);

			#If its the listening machine
			if (unpack ('H12', $lg) == sprintf('%x', 0x4061864e4439)) {
				
				#Then we care
				$packetpickup = 1;
				
			}
			
		#If we are less that 11 Bytes into the frame (Src Mac feild)
		} elsif ($i < 11) {
			
			#Define cut length of 6 bytes
			$cutlength = 6;
			
			#Cut off the next bit of frame
			$lg = substr($packet, $i, $cutlength);
		
			#Increment the length counter
			$i += 6;
			
			#populate this var with the hex unpacked var
			$ethertypeunpack = unpack ('H12', $lg);
		
		#If we are further than 11 bytes
		} elsif ($i >= 11) {
			
			#but between 11 and 13 (2 byte ethertype feild)
			if ($i <= 13) {
			
				#Define a cut length of 2
				$cutlength = 2;
				
				#Cut the front off the frame
				$lg = substr($packet, $i, $cutlength);
				
				#Increment the counter
				$i += 2;
				
				#Populate this car with the hex unpacked 
				$ethertypeunpack = unpack ('H4', $lg);
				
				#If we care abut this frame
				if ($packetpickup == 1){
					#We check the ethertype feild to see if it's ARP
					if (unpack ('H4', $lg) == sprintf('%x', 0x0806)) {
						
						#If it is ARP, we still care about the frame
						$packetpickup = 1;
						#print "Host Found: ";
						
					} else {
						
						#If the frame is not ARP, we don't care
						$packetpickup = 0;
					}
				}
			
			#If we hit the src protocol address
			} elsif (($i > 27) && ($i <= 30)){
			
				#Define a cut length of 1
				$cutlength = 1;
				
				#Cut the front off the frame (The first byte of the IP Address)
				$lg = substr($packet, $i, $cutlength);
				
				#Increment the counter
				$i += 1;
				
				#Populate this car with the hex unpacked 
				$ethertypeunpack = unpack ('H2', $lg);
				
				#If we care about this arp reply
				if ($packetpickup == 1) {
				
					#We output the decimal value of the hex
					#print hex $ethertypeunpack;
					#and a dot
					#print ".";
					
					push(@iparray, hex $ethertypeunpack);
				}
				
			#If we are on the last byte of the src protocol address
			} elsif (($i > 30) && ($i <= 31)){
				
				#Define a cut length of 1
				$cutlength = 1;
				
				#Cut the front off the frame
				$lg = substr($packet, $i, $cutlength);
				
				#Increment the counter
				$i += 1;
				
				#Populate this car with the hex unpacked 
				$ethertypeunpack = unpack ('H2', $lg);
				
				#Do we care?
				if ($packetpickup == 1) {
					
					#Print the dec value of the hex
					#print hex $ethertypeunpack;
					#And since this is the end, we do a new line
					#print "\n";
					
					push(@iparray, hex $ethertypeunpack);
				}
				
			#if it is after 13, we are hitting the rest of the packet
			} else { 
				
				#We set the cut length of 8 bytes
				$cutlength = 2;
				
				#Cut the front off the frame
				$lg = substr($packet, $i, $cutlength);
				
				#Increment the counter
				$i += 2;
				
				#AND populate that variable with the unpacked hex
				$ethertypeunpack = unpack ('H4', $lg);

			}
			
		}
		
	}
	
	if ($packetpickup == 1) {
		#print "$iparray[0].$iparray[1].$iparray[2].$iparray[3]\n";
		push (@foundhosts, "$iparray[0].$iparray[1].$iparray[2].$iparray[3]");
	}
}

#Sub to find the mac address of a chose interface
sub get_interface_information {
	
	#Get the interface from args
	my $interface = $_;
	
	################GET MAC
	#Run ifconfig for the selected inteface and grep the mac
	my $macifconfig = `/sbin/ifconfig $interface | grep HWaddr`;
	#Split the results to get just the colon delimtered mac
	my ($maclabel, $actualmac) = split(/HWaddr /, $macifconfig);
	#Kill the colons so we have each byte in a seperate variable
	my ($a, $b, $c, $d, $e, $f) = split(/:/, $actualmac);
	#Populate mymac var with compiled mac
	my $mymac = "0x$a$b$c$d$e$f";
	########################
	
	################GET IP and SUBNET
	my $ipifconfig = `/sbin/ifconfig $interface | grep inet\\ addr`;
	my ($g, $h, $i, $j, $k) = split(/\s+/, $ipifconfig);
	my ($l, $myip) = split(/:/, $i);
	my ($l, $mysubnet) = split(/:/, $k);
	#############################
	
	#Put them all together and return them
	return $mymac, $myip, $mysubnet;
}

#Sub to convert the period delimtered IP to hex
sub get_hex_of_ip {
	
	#Get those ARgs
	my ($hexip, $userdata) = @_;
	
	#Spit the IP Address into bytes
	my @myipbytes = split(/\./, $hexip);
	
	#Initalize an array to hold the packed up bytes
	my @mypackedbytes;

	#loop through the bytes
	for (my $y = 0; $y <= 3; $y++) {

		#Pack the bytes and chuck them in the array
		$mypackedbytes[$y] = pack('B8', sprintf('%.8b', $myipbytes[$y]));

	}

	#Merge the bytes into the binary IP Address
	return "$mypackedbytes[0]$mypackedbytes[1]$mypackedbytes[2]$mypackedbytes[3]";
	
}

#sub the get the network bits from the IP and Subnet
sub get_networkbits_from_ip {
	
	#Get those args
	my ($ipp, $subb) = @_;
	
	#Split the IP
	my @splitip = split(/\./, $ipp);

	#Initalize the array
	my @binarybitsip;
		#Loop through the decimal ip address
	for (my $s = 0; $s <= 3; $s++) {
		#convert it to binary
		$binarybitsip[$s] = sprintf('%.8b', $splitip[$s]);
	}
	
	#Combine the bytes
	my $allbinaryip = "$binarybitsip[0]$binarybitsip[1]$binarybitsip[2]$binarybitsip[3]";

	#split the subnet
	my @splitsubmet = split(/\./, $subb);
		#Initalize the array
	my @binarybitssubnet;
		#Loop through the decimal ip address
	for (my $v = 0; $v <= 3; $v++) {
		#convert it to binary
		$binarybitssubnet[$v] = sprintf('%.8b', $splitsubmet[$v]);
	}
	
	#Combine the bytes
	my $allbinarysubnet = "$binarybitssubnet[0]$binarybitssubnet[1]$binarybitssubnet[2]$binarybitssubnet[3]";
	
	#Split the subnet by 1s to get the last network bit
	my @splitsubnetresult= split(/1/, $allbinarysubnet);
	
	#Get the length of the hosts bits
	my $hostbitslength = length @splitsubnetresult[$#splitsubnetresult];

	
	#Cut the end off the network address
	my $networkbinaryip = substr($allbinaryip, 0, (32 - $hostbitslength));

	#Get the host bits by creating an empty 8bit number
	my $hostbinaryip = sprintf('%.*b',$hostbitslength, 0);
	
	#Return the binary ip, subnet, and the length of the hosts segment
	return $networkbinaryip, $hostbinaryip, length $hostbinaryip;
	
}
