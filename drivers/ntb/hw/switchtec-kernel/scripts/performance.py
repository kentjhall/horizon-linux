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

import test
import timeit

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--it", default=100, type=int,
                        help="number of iterations to test")
    parser.add_argument("device", default="/dev/switchtec0", nargs="?",
                        help="switchtec device to test")
    parser.add_argument('args', nargs=argparse.REMAINDER)
    options = parser.parse_args()

    st = test.Switchtec(options.device, verbose=False)

    def test():
        st.echo(b"ABCD")

    time = timeit.timeit(test, number=options.it)

    print("{:.2f} MRPC commands / s".format(options.it / time))
