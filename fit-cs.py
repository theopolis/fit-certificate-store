#!/usr/bin/env python

#  Teddy Reed <teddy.reed@gmail.com>
#  Copyright (c) 2016-present
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree.

import argparse
import jinja2
import os
import sys
import tempfile

from Crypto.PublicKey import RSA
from Crypto.Util import number
from distutils import spawn

def genWords(bits, num):
    words = []
    b2_32 = 2 ** 32L
    for i in xrange(bits / 32):
        n = num % b2_32
        words.insert(0, "0x%x" % n)
        num = num >> 32
    return words

def genKey(name, filename):

    #print("Reading public key: %s" % filename)
    with open(filename, 'rU') as fh:
        pubkey_data = fh.read()
    pubkey = RSA.importKey(pubkey_data)

    # Only support 2048 or 4096 bit keys
    size = number.size(pubkey.n)
    if size < 2000:
        print("Error: Key size is: %d" % pubkey.size())
        sys.exit(1)

    key = {}
    key["name"] = name
    key["size"] = "%s" % size
    key["bits"] = "0x%x" % size

    # Here be dragons, this really doesn't handle a u64.
    key["exponent"] = "0x0 0x%x" % pubkey.e

    b2_32 = 2 ** 32L
    n0_invp = (number.inverse(pubkey.n, b2_32) - b2_32) * -1
    key["n0inverse"] = "0x%x" % n0_invp

    modulus = pubkey.n
    key["modulus"] = " ".join(genWords(size, modulus))

    r = 2 ** size
    r_squared = (r * r) % modulus
    key["rsquared"] = " ".join(genWords(size, r_squared))
    return key

def main(args):
    if not args.no_out and args.output == '':
        print("Either provide an OUTPUT_DTB or use --no-out")
        return 1
    if not os.path.exists(args.template):
        print("Cannot find template input: %s" % args.template)
        return 1
    if not os.path.exists(args.keys):
        print("Cannot find key directory: %s" % args.keys)
        return 1

    with open(args.template, "rU") as fh:
        template_data = fh.read()

    keys = []
    for base, _, filenames in os.walk(args.keys):
        for filename in filenames:
            key_name, extension = os.path.splitext(filename)
            if extension != "." + args.ext:
                continue
            keys.append(genKey(os.path.basename(key_name),
                os.path.join(base, filename)))

    source = jinja2.Template(template_data).render(keys=keys,
        algorithm=args.algorithm, node=args.required_node)
    if args.no_out:
        print(source)
        return 0

    dtc = spawn.find_executable('dtc')
    if dtc == '':
        print("Cannot find 'dtc' in your path, maybe try using --no-out")
        return 1
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(source)
        tmp.flush()
        spawn.spawn(
            [dtc, "-I", "dts", "-O", "dtb", "-o", args.output, tmp.name])
    print("Write certificate store DTB: %s" % args.output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Generate a FIT certificate store (a DTB).")
    parser.add_argument("keys", metavar="DIRECTORY",
        help="Path to directory containing public keys")
    parser.add_argument("output", nargs='?', metavar="OUTPUT_DTB", default='',
        help="Output path of compiled certificate store (dtb)")

    parser.add_argument("--ext", default="pub", metavar="pub",
        help="Search for public keys with this file extension")
    parser.add_argument("--template", default="store.dts.in", metavar="PATH",
        help="Certificate store template")
    parser.add_argument("--no-out", default=False, action="store_true",
        help="Print the resultant source instead of compiling")
    parser.add_argument("--algorithm", default="sha256", metavar="sha256",
        help="Override default hashing algorithm")
    parser.add_argument("--required-node", default="conf", metavar="conf",
        help="Set the required node (default=conf)")
    args = parser.parse_args()
    sys.exit(main(args))
