#!/usr/bin/env python3
########################################################################
##
## Microsemi Switchtec(tm) PCIe Management Driver Test Script
## Copyright (c) 2016, Microsemi Corporation
##
## This program is free software; you can redistribute it and/or modify it
## under the terms and conditions of the GNU General Public License,
## version 2, as published by the Free Software Foundation.
##
## This program is distributed in the hope it will be useful, but WITHOUT
## ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
## FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
## more details.
##
########################################################################

import sys
import os
import struct
import unittest
import fcntl
import time
import select

class Switchtec(object):
    def __init__(self, path, verbose=False):
        super(Switchtec, self).__init__()
        self.fd = os.open(path, os.O_RDWR)
        self.verbose = verbose

        self.poll_obj = select.poll()
        self.poll_obj.register(self.fd, select.POLLIN | select.POLLERR)

    def _vprint(self, *args, **kwargs):
        if not self.verbose:
            return

        print(*args, **kwargs)

    def start_cmd(self, cmd_id, payload=b""):
        try:
            data = struct.pack("<L", cmd_id) + payload

            self._vprint("Cmd {}   - IN: ".format(cmd_id), repr(data))
            os.write(self.fd, data)
        except OSError as e:
            self._vprint("  Error Occured:", e)
            raise

    def read_resp(self, outdata_len=0):
        try:
            data = os.read(self.fd, 4+outdata_len)
            ret = struct.unpack("<L", data[:4])[0]

            self._vprint("  Ret {}   OUT:".format(ret), repr(data))

            return ret, data[4:]
        except OSError as e:
            self._vprint("  Error Occured:", e)
            raise

    def cmd(self, cmd_id, payload=b"", outdata_len=0):
        self.start_cmd(cmd_id, payload)
        return self.read_resp(outdata_len)

    def echo(self, payload=b""):
        assert len(payload) <= 4

        return self.cmd(65, payload, len(payload))

    def set_nonblocking(self, enabled=True):
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL, 0);

        if enabled:
            flags |= os.O_NONBLOCK
        else:
            flags &= ~os.O_NONBLOCK

        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags)

    def poll(self, timeout=1000):
        ret = self.poll_obj.poll(timeout)
        return len(ret) > 0

class SwitchtecTests(unittest.TestCase):
    st = None

    def test_echo(self, tries = [b"\xAA"*4, b"\x55"*4]):

        for data_in in tries:
            exp = bytes([~x & 0xFF for x in data_in])

            ret, data_out = self.st.echo(data_in)

            self.assertEqual(ret, 0)
            self.assertEqual(data_out, exp)

    def test_invalid(self):
        with self.assertRaises(OSError):
            self.st.cmd(62)
        self.test_echo(tries=[b"\x11\xEE"*2])

    def test_noevent(self):
        ret, data_out = self.st.cmd((1 << 16) | 65, b"\x77"*4, 4)
        self.assertEqual(ret, 0)
        self.assertEqual(data_out, b"\x88"*4)
        self.test_echo(tries=[b"\xFF"*4])

    def test_double_write(self):
        self.st.start_cmd(65, b"\xA5")
        with self.assertRaises(OSError):
            self.st.start_cmd(65, b"\xA5")

        ret, data_out = self.st.read_resp(1)
        self.assertEqual(ret, 0)
        self.assertEqual(data_out, b"\x5A")

    def test_read_without_write(self):
        with self.assertRaises(OSError):
            self.st.read_resp(1)

    def test_nonblocking(self):
        try:
            self.st.set_nonblocking(True)
            self.st.start_cmd(65, b"\x5A")

            with self.assertRaises(OSError):
                self.st.read_resp(1)

            while True:
                time.sleep(0.001)
                try:
                    ret, data_out = self.st.read_resp(1)
                    self.assertEqual(ret, 0)
                    self.assertEqual(data_out, b"\xA5")
                    break
                except OSError:
                    continue

        finally:
            self.st.set_nonblocking(False)

    def test_poll(self):
        try:
            self.st.set_nonblocking(True)
            self.st.start_cmd(65, b"\x11\x22")

            with self.assertRaises(OSError):
                self.st.read_resp(2)

            while not self.st.poll():
                pass

            ret, data_out = self.st.read_resp(2)
            self.assertEqual(ret, 0)
            self.assertEqual(data_out, b"\xEE\xDD")

        finally:
            self.st.set_nonblocking(False)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="be verbose")
    parser.add_argument("device", default="/dev/switchtec0", nargs="?",
                        help="switchtec device to test")
    parser.add_argument('args', nargs=argparse.REMAINDER)
    options = parser.parse_args()

    SwitchtecTests.st = Switchtec(options.device, verbose=options.verbose)

    unittest.main(argv=sys.argv[0:1] + options.args)
