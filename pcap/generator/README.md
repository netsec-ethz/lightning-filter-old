this subdirectory contains two script to generate new SCION pcap files.
The scripts are all currently hard-coded and if different pcap files should be generated
the scripts has to be modified. The most important parameter is the packet size, 
which can be achieved by modifying the values array in the main function.
All other build parameters of the SCION packets must be changed in the corresponding build functions.

Generally
scion_scappy_secX: generates secX packets with key "aaaabbbbccccdddd"
scion_scappy_norm: generates standard SCION packets.