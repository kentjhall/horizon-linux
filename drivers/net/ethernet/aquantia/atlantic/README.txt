Linux* aQuantia AQtion Driver for the aQuantia Multi-Gigabit PCI Express Family of
Ethernet Adapters
=============================================================================

Contents
========

- Important Note
- In This Release
- Identifying Your Adapter
- Building and Installation
- Command Line Parameters
- Additional Configurations
- Support

IMPORTANT NOTE
==============

WARNING:  The AQtion driver compiles by default with the LRO (Large Receive
Offload) feature enabled.  This option offers the lowest CPU utilization for
receives, but is completely incompatible with *routing/ip forwarding* and
*bridging*.  If enabling ip forwarding or bridging is a requirement, it is
necessary to disable LRO using compile time options as noted in the LRO
section later in this document.  The result of not disabling LRO when combined
with ip forwarding or bridging can be low throughput or even a kernel panic.

In This Release
===============

This file describes the aQuantia AQtion Driver for the aQuantia Multi-Gigabit PCI Express Family of
Ethernet Adapters.  This driver supports the linux kernels >= 3.10, 
and includes support for x86_64 and ARM Linux system.

This release contains source tarball and (optional) src.rpm package.

Identifying Your Adapter
========================

The driver in this release is compatible with AQC-100, AQC-107, AQC-108 based ethernet adapters.


SFP+ Devices (for AQC-100 based adapters)
----------------------------------

This release tested with passive Direct Attach Cables (DAC) and SFP+/LC Optical Transceiver.

Building and Installation
=========================

To manually build this driver:
------------------------------------------------------------
1. Make sure you have all the environment to build standalone kernel module.
   On debian based systems you may do the following:

	sudo apt install linux-headers build-essential

2. Move the base driver tar file to the directory of your choice. For example,
   use /home/username/aquantia.
   Untar/unzip archive:

	cd ~/aquantia
	tar zxf Aquantia-AQtion-x.y.z.tar.gz

3. Change to the driver src directory:

	cd Aquantia-AQtion-x.y.z/

4. Compile the driver module:
	make

5. Load the module:
	sudo insmod atlantic.ko

6. Unload the driver
	sudo rmmod atlantic

7. Install the driver in the system
	make && make install

driver will be in:

	/lib/modules/`uname -r`/aquantia/atlantic.ko

8. Uninstall the driver:
	make uninstall
or run the following commands:
	sudo rm -f /lib/modules/`uname -r`/aquantia/atlantic.ko
	depmod -a `uname -r`

Alternatively build and install driver with dkms
------------------------------------------------------------
1. Make sure you have all the environment to build standalone kernel module.
   On debian based systems you may do the following:

	sudo apt-get install linux-headers-`uname -r` build-essential gawk dkms

   On redhat based systems you may do the following:

	sudo yum install kernel-devel-`uname -r` gcc gcc-c++ make gawk dkms

2. Move the base driver tar file to the directory of your choice. For example,
   use /home/username/aquantia.
   Untar/unzip archive:

	cd ~/aquantia
	tar zxf Aquantia-AQtion-x.y.z.tar.gz

3. Change to the driver source directory:

	cd Aquantia-AQtion-x.y.z/

4. Build and install driver:

	sudo ./dkms.sh install

driver will be in:

	/lib/modules/`uname -r`/updates/dkms/atlantic.ko

5. Uninstall the driver:

	sudo ./dkms.sh uninstall

Install driver on Debian\Ubuntu using atlantic-x.y.z.deb
------------------------------------------------------------
1. Make sure you have all the environment to build standalone kernel module. Execute the commands:
	sudo apt-get install linux-headers-`uname -r`

2. Move the atlantic-x.y.z.deb file to the directory of your choice. For example,
   use /home/username/aquantia. 
 
3. Execute the commands:
    cd /home/username/aquantia
    sudo apt-get install ./atlantic-x.y.z.deb
	
    After this driver will be installed.
    (You can check this via "dpkg -l | grep -i atlantic")

4. Uninstall the driver:
   Run the following commands:
   sudo dpkg -P atlantic

	
Alternatively you can use  atlantic-x.y.z.noarch.rpm
------------------------------------------------------------
1. Make sure you have all the environment to build standalone kernel module. Execute the commands:
	sudo yum install kernel-devel-`uname -r`

2. Move the atlantic-x.y.z.noarch.rpm file to the directory of your choice. For example,
   use /home/username/aquantia. 
 
3. Execute the commands:
    cd /home/username/aquantia
    sudo yum install ./atlantic-x.y.z.noarch.rpm
	
    After this driver will be installed.
    (You can check this via "rpm -qa | grep -i atlantic")

4. Uninstall the driver:
   Run the following commands:
   sudo rpm -e atlantic-x.y.z.noarch

Check that the driver is working
------------------------------------------------------------
	
1. Verify ethernet interface appears:
	ifconfig
	or
	ip addr show
	
	If no new interface appears, check dmesg output.
	If you see "Bad firmware detected" please update firmware on your ethernet card.

2. Assign an IP address to the interface by entering the following, where
   x is the interface number:

	ifconfig ethX <IP_address> netmask <netmask>
    or
	ip addr add <IP_address> dev <DEV>

3. Verify that the interface works. Enter the following, where <IP_address>
   is the IP address for another machine on the same subnet as the interface
   that is being tested:

	ping  <IP_address>
or (for IPv6)
	ping6 <IPv6_address>

4. Check the correct version of the driver is active (assume interface is eth1):

        ethtool -i eth1

Troubleshooting
-----------------------

Some distributions do not provide kernel sources ready for thirdparty module build.
In general, the following could be used to prepare kernel source tree for build:

	sudo su
	cd /lib/modules/`uname -r`/build
	make oldconfig
	make prepare
	make modules_prepare

Command Line Parameters
=======================
The following command line parameters are available on atlantic driver:

aq_itr -Interrupt throttling mode
----------------------------------------
Accepted values: 0, 1, 0xFFFF
Default value: 0xFFFF
0      - Disable interrupt throttling.
1      - Enable interrupt throttling and use specified tx and rx rates.
0xFFFF - Auto throttling mode. Driver will choose the best RX and TX
         interrupt throtting settings based on link speed.

aq_itr_tx - TX interrupt throttle rate
----------------------------------------
Accepted values: 0 - 0x1FF
Default value: 0
TX side throttling in microseconds. Adapter will setup maximum interrupt delay
to this value. Minimum interrupt delay will be a half of this value

aq_itr_rx - RX interrupt throttle rate
----------------------------------------
Accepted values: 0 - 0x1FF
Default value: 0
RX side throttling in microseconds. Adapter will setup maximum interrupt delay
to this value. Minimum interrupt delay will be a half of this value

Note: ITR settings could be changed in runtime by ethtool -c means (see below)

aq_rxpageorder
----------------------------------------
Default value: 0
RX page order override. Thats a power of 2 number of RX pages allocated for
each descriptor. Received descriptor size is still limited by AQ_CFG_RX_FRAME_MAX.
Increasing pageorder makes page reuse better (actual on iommu enabled systems).

aq_rx_refill_thres
----------------------------------------
Default value: 32
RX refill threshold. RX path will not refill freed descriptors until the
specified number of free descriptors is observed. Larger values may help
better page reuse but may lead to packet drops as well.


Config file parametes
=======================
Some parameters can be changed in the {source_dir}/aq_cfg.h file:

AQ_CFG_VECS_DEF
------------------------------------------------------------
Number of queues
Valid Range: 0 - 8 (up to AQ_CFG_VECS_MAX)
Default value: 4

AQ_CFG_IS_RSS_DEF
------------------------------------------------------------
Enable/disable Receive Side Scaling

This feature allows the adapter to distribute receive processing
across multiple CPU-cores and to prevent from overloading a single CPU core.

Valid values
0 - disabled
1 - enabled

Default value: 1

AQ_CFG_NUM_RSS_QUEUES_DEF
------------------------------------------------------------
Number of queues for Receive Side Scaling
Valid Range: 0 - 4 (up to AQ_CFG_VECS_DEF)

Default value: 4

AQ_CFG_IS_LRO_DEF
------------------------------------------------------------
Enable/disable Large Receive Offload

This offload enables the adapter to coalesce multiple TCP segments and indicate
them as a single coalesced unit to the OS networking subsystem.
The system consumes less energy but it also introduces more latency in packets processing.

Valid values
0 - disabled
1 - enabled

Default value: 1

AQ_CFG_TX_CLEAN_BUDGET
----------------------------------------
Maximum descriptors to cleanup on TX at once.
Default value: 256

After the aq_cfg.h file changed the driver must be rebuilt to take effect.

Additional Configurations
=========================
  Viewing Link Messages
  ---------------------
  Link messages will not be displayed to the console if the distribution is
  restricting system messages. In order to see network driver link messages on
  your console, set dmesg to eight by entering the following:

       dmesg -n 8

  NOTE: This setting is not saved across reboots.

  Jumbo Frames
  ------------
  The driver supports Jumbo Frames for all adapters. Jumbo Frames support is
  enabled by changing the MTU to a value larger than the default of 1500.
  The maximum value for the MTU is 16000.  Use the ifconfig command to
  increase the MTU size.  For example:

        ifconfig <ethX> mtu 9000 up

  ethtool
  -------
  The driver utilizes the ethtool interface for driver configuration and
  diagnostics, as well as displaying statistical information. The latest 
  ethtool version is required for this functionality.
 
  
  NAPI
  ----
  NAPI (Rx polling mode) is supported in the atlantic driver. 

  See ftp://robur.slu.se/pub/Linux/net-development/NAPI/usenix-paper.tgz for 
  more information on NAPI.

Supported ethtool options
============================
 Viewing adapter settings
 ---------------------
 ethtool <ethX>
 
 Output example:
 Settings for enp1s0:
        Supported ports: [ ]
        Supported link modes:   100baseT/Full
                                1000baseT/Full
                                10000baseT/Full
        Supported pause frame use: Symmetric
        Supports auto-negotiation: Yes
        Advertised link modes:  100baseT/Full
                                1000baseT/Full
                                10000baseT/Full
        Advertised pause frame use: Symmetric
        Advertised auto-negotiation: Yes
        Speed: 10000Mb/s
        Duplex: Full
        Port: FIBRE
        PHYAD: 0
        Transceiver: external
        Auto-negotiation: on
        Link detected: yes

 ---
 Note: AQrate speeds (2.5/5 Gb/s) will be displayed only with linux kernels > 4.10.
    But you can still use these speeds:
	ethtool -s eth0 autoneg off speed 2500
		
 Viewing adapter information
 ---------------------
 ethtool -i <ethX>

 Output example:
 driver: atlantic
 version: 1.6.9.0
 firmware-version: 1.5.49
 expansion-rom-version:
 bus-info: 0000:01:00.0
 supports-statistics: yes
 supports-test: no
 supports-eeprom-access: no
 supports-register-dump: yes
 supports-priv-flags: no

 Viewing Ethernet adapter statistics:
 ---------------------
 ethtool -S <ethX>

 Output example:
 NIC statistics:
     InPackets: 13238607
     InUCast: 13293852
     InMCast: 52
     InBCast: 3
     InErrors: 0
     OutPackets: 23703019
     OutUCast: 23704941
     OutMCast: 67
     OutBCast: 11
     InUCastOctects: 213182760
     OutUCastOctects: 22698443
     InMCastOctects: 6600
     OutMCastOctects: 8776
     InBCastOctects: 192
     OutBCastOctects: 704
     InOctects: 2131839552
     OutOctects: 226938073
     InPacketsDma: 95532300
     OutPacketsDma: 59503397
     InOctetsDma: 1137102462
     OutOctetsDma: 2394339518
     InDroppedDma: 0
     Queue[0] InPackets: 23567131
     Queue[0] OutPackets: 20070028
     Queue[0] InJumboPackets: 0
     Queue[0] InLroPackets: 0
     Queue[0] InErrors: 0
     Queue[1] InPackets: 45428967
     Queue[1] OutPackets: 11306178
     Queue[1] InJumboPackets: 0
     Queue[1] InLroPackets: 0
     Queue[1] InErrors: 0
     Queue[2] InPackets: 3187011
     Queue[2] OutPackets: 13080381
     Queue[2] InJumboPackets: 0
     Queue[2] InLroPackets: 0
     Queue[2] InErrors: 0
     Queue[3] InPackets: 23349136
     Queue[3] OutPackets: 15046810
     Queue[3] InJumboPackets: 0
     Queue[3] InLroPackets: 0
     Queue[3] InErrors: 0

 Disable GRO when routing/bridging
 ---------------------------------
 Due to a known kernel issue, GRO must be turned off when routing/bridging. 
 Its can be done with command:
 
 ethtool -K <ethX> gro off

 
 Disable LRO when routing/bridging
 ---------------------------------
 Due to a known kernel issue, LRO must be turned off when routing/bridging. 
 Its can be done with command:
 
 ethtool -K <ethX> lro off

 Interrupt coalescing support
 ---------------------------------
 ITR mode, TX/RX coalescing timings could be viewed with:
 
 ethtool -c <ethX>
 
 and changed with:
 
 ethtool -C <ethX> tx-usecs <usecs> rx-usecs <usecs>
 
 To disable coalescing:

 ethtool -C <ethX> tx-usecs 0 rx-usecs 0 tx-max-frames 1 tx-max-frames 1
 
 Wake on LAN support
 ---------------------------------

 WOL support by magic packet:

 ethtool -s <ethX> wol g
 
 To disable WOL:

 ethtool -s <ethX> wol d

Private flags (testing)
 ---------------------------------

 Atlantic driver supports private flags for hardware loopback testing:

	$ ethtool --show-priv-flags ethX

	Private flags for ethX:
	DMASystemLoopback  : off
	PKTSystemLoopback  : off
	DMANetworkLoopback : off
	PHYInternalLoopback: off
	PHYExternalLoopback: off

 Example:

 	$ ethtool --set-priv-flags ethX DMASystemLoopback on
 
 DMASystemLoopback:   DMA Host loopback.
 PKTSystemLoopback:   Packet buffer host loopback.
 DMANetworkLoopback:  Network side loopback on DMA block.
 PHYInternalLoopback: Internal loopback on Phy.
 PHYExternalLoopback: External loopback on Phy (with loopback ethernet cable).


Support
=======

If an issue is identified with the released source code on the supported
kernel with a supported adapter, email the specific information related
to the issue to support@aquantia.com

License
=======

aQuantia Corporation Network Driver
Copyright(c) 2014 - 2018 aQuantia Corporation.

This program is free software; you can redistribute it and/or modify it
under the terms and conditions of the GNU General Public License,
version 2, as published by the Free Software Foundation.
