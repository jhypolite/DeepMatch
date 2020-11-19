# DeepMatch

## Setup and Installation

### DeepMatch Host

Install the Netronome SDK6 Run Time Environment, Hardware debug server, and BSP according to their documentation.

We used the following configuration for the DeepMatch host:
* Dell PowerEdge R720 with dual Intel Xeon E5-2650 v2 8-core 2.60 GHz processors and 64 GB DDR3 1600MHz RAM
* Netronome Agilio-CX Dual-Port 40 Gigabit Ethernet Intelligent Server Adapter (Part ID: ISA-4000-40-2-2)
* Ubuntu 16.04 LTS
* Python 2.7
* Enable SR-IOV in the bios

### Netronome SDK IDE Development Host

Install the Netronome SDK IDE according to their documentation. Note that the current version of DeepMatch is written in P4v14 (not P4v16). We used a Windows 10 host to run the IDE.

### Traffic Generator

We used the following configuration for our traffic generator host:
* Dell R720 with dual Intel Xeon E5-2680 v2 10-core 2.80GHz processors and 256 GB DDR3 1866 MHz RAM
* Mellanox MCX456A-ECA ConnectX-4 dual-port QSFP28 100GbE
* Unbuntu 16.04 LTS
* Anaconda3 with Python 3.7.8 and Python 2.7.12
* dpdk-17.08.1 with 1 GB Hugepages
* pktgen-3.4.9
* latest version of tcpreplay
* latest version of python scapy
* python fabric (http://www.fabfile.org/) is used to automate many of our experiments, including interacting with the NFP card remotely.

### Switch backbone

We use an Arista DCS-7050QX-32-R 32x Port 40G QSFP+ Layer 3 Switch

## Build

Use Netronome Programmer Studio (we used version 6.0.3.1 build 3241) to create a new project with the DeepMatch P4v14 source files.

Useful Programmer Studio Settings:

* Chip Setting:
  * nfp-6xxxc-b0 
* Project Configuation (see "P4/Managed C" tab):
  * Number of worker MEs: 80
  * Use Shared Code Store: enable
  * Reduced thread usage: enable
* Optional Components (see "P4/Managed C" tab):
  * GRO: disable
* Preprocessor definitions (see the "General" tab):
  * PHAST_FX_PY: where X is no. flows and Y is OoO buffer size; e.g. PHAST_F321_P100
  * PHAST_DFA_X: where X identifies the DFA to load; e.g. PHAST_DFA_MAL_BACKDOOR
  * PHAST_DLOC_X: where X identifies which memory to place the DFA; e.g. CLS, CTM, IMEM, EMEM
  * PHAST_LOCK: enables all locks (needed when reordering is turned on)

Build the code and transfer the following files to the DeepMatch host:
  * file.nffw
  * file.p4cfg
  * out/pif_design.json

## Usage (Manual Eval)

### Running DeepMatch

#### Start the runtime environment (only need to do this once):
`systemctl start nfp-sdk6-rte1`

#### Check that runtime environment is running properly:
`sudo netstat -tulpn | grep -E 'pif_rte|nfp-sdk-hwdbgs'`

#### Load the program:
`rtecli -p 20207 design-load -p pif_design.json -f file.nffw`

#### Load the tables:
`rtecli -p 20207 config-reload -c file.p4cfg`

#### Check that everything loaded properly:
`rtecli -p 20207 status`

Another way to check that firmware is loaded:

`sudo /opt/netronome/bin/nfp-nffw status -n 1`

#### Load DFA and stack variables:
`sudo setup_experiment.py -o v`

#### unload the program:
`rtecli -p 20207 design-unload`

One way to check the status

`rtecli -p 20207 status`

Another way to check the status

`sudo /opt/netronome/bin/nfp-nffw status -n 1`

### Evaluating DeepMatch

Use tcpreplay, dpdk/pktgen, or your favorite tools to transmit/receive packets to/from DeepMatch.

### Checking the Evaluation Results

#### Check if all flows closed properly:

`sudo /opt/netronome/bin/nfp-rtsym -n 1 -L | grep flow_ht`

Use this output to determine the location and size of flow_ht. Then dump the variable's memory into a file and check the value.

`sudo /opt/netronome/bin/nfp-rtsym -n 1 -L | grep pkt_ht`

Use this output to determine the location and size of pkt_ht. Then dump the variable's memory into a file and check the value.

#### Check for dropped packets:

One way to check

`sudo /opt/netronome/bin/nfp  -n 1 -m mac -e show port stats 0 0-8`

Another way to check

`rtecli -p 20207 counters list-system`

## Usage (Automated Eval)

We use Python fabric to automate the manual evaluation steps.
http://www.fabfile.org/
