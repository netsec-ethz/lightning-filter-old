This is the readme for the Lightning filter prototype


## Dependencies
In order to build the project, you will need:
- dpdk 19.05 installed in the home directory, with the name `~/dpdk-19.05`
- gcc 5
- yasm
- go 1.11

## The directory contains the following:

- src/
contains the entire source code for the Lighning filter, more specifically all c source files.
src/config7 contains the config files, which can be modified, although the format specification must not be changed.
src/lib/ contains the necessary dependencies, especially the CMAC assembly implementation and the key_manager.so file.
The src directory provides a buildall.sh script and a run.sh script, for more information how to run the code,
consult the RUN_INSTRUCTIONS.md file. To build we use make.

- go/
Contain all go source code. More specifically the metrics_exporter and the key_manager.
The metrics exporter must be run in addition to the Lighning filter if metrics shall be exported.
The key_manager subdirectoy contains a script to compile and move the libarary to the correct location.

- testing/
contains the source code files for the unit tests. For unit testing we use cmocka. Due to difficulties with building
the units tests are currently integrated into the apllication itself and are always run if the main unit test call is
not commented out in the application.c file. 

- prometheus_config/ 
contains a simple config file for prometheus in order to create a job
for both the metrics exporter and the Prometheus node exporter

- spirent/
contains the spirent config files that were used during this thesis for evaluation purposes. They can be used as a
reference when creating new streamBlocks. 

- pcap/
contains a number of pcap files with different SCION packets that can be used to create new streamBlocks in Spirent.
The directory contains to scripts to generate new pcap file. However, these scripts are very simple and must be modifed
for any specific generator changes.


## Structure and Modifcations
The project is an extension of two previous projects, thus there are a few artifacts left in the codebase.
There are some, in retrospect, questionable design decisions and the code is not optimally structured. This is largely a consequence
of having multiple authors and last minute design changes.

In general the most important source file is the scionfwd.c source file. 
For anyone aiming to understand the code or wishing to extend the project, these functions are essential to understand:

- scion_filter_main() contains the entire DPDK set-up (port, lcore, memory and queue allocation)
- scionfwd_main_loop() contains the main processing core loop (data-plane)
- scionfwd_should_forward() contains the decision logic for the data-plane
- key_manager_main_init()& key_manager_main_loop() contain the key-manager code
- dos_init()& dos_main_loop() contain the rate-limiter code
