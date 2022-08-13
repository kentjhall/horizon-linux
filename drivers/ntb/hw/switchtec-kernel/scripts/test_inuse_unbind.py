#!/usr/bin/env python3

import os
import time


fd = os.open("/dev/switchtec0", os.O_RDWR)

dev_path = os.path.realpath("/sys/class/switchtec/switchtec0/device")
pci_name = os.path.basename(dev_path)

f = open(os.path.join(dev_path, "driver", "unbind"), "w")
f.write(pci_name + "\n")
f.close()

time.sleep(5)

os.close(fd)

time.sleep(1)

f = open("/sys/bus/pci/drivers/switchtec/bind", "w")
f.write(pci_name + "\n")
f.close()
