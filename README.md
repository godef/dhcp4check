# dhcp4check

## Check whether DHCP server is setup correctly. 
Send out DHCP DISCOVER packet, and check the DHCP OFFER packet.


## Why this tool? 
Trying to solve these problems with other tools:
* If we bind to local address to send out DHCP DISCOVER packet, it cannot receive the broadcasted DHCP OFFER. Maybe that's because it is just listening to an specific local address, and not listening to the broadcast address (this is probably the issue of the underlying library implementation)
* If we don't bind to a local address, we couldn't send out the request to 255.255.255.255. "Fatal error: Sendto error". So, the work around is to send to a broadcast address of the given local address's interface, mostly x.x.x.255 for /24 network.
