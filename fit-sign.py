#!/usr/bin/env python

import os
import tempfile
import argparse
import StringIO
import sys

from distutils import spawn

from pyfdt import pyfdt


def write_content(offset, data):
    with open(args.output, 'a') as fh:
        fh.seek(offset)
        fh.write(data)


def write_firmware(filename):
    with open(filename) as fh:
        signed_content = fh.read()

    if args.subordinate is not None:
        updated_fit = inject_subordinate(signed_content, args.subordinate)
        signed_content = updated_fit + signed_content[len(updated_fit):]

    write_content(args.offset, signed_content)
    padding = args.max_size - len(signed_content)
    write_content(args.offset + len(signed_content), '\0' * padding)


def write_os(filename):
    with open(filename) as fh:
        signed_content = fh.read()
        write_content(args.os, signed_content)


def inject_subordinate(signed_content, path):
    with open(path) as fh:
        sub_data = fh.read()
        # Read the subordinate key store as a FDT.
        fit_io = StringIO.StringIO(sub_data)
        dtb = pyfdt.FdtBlobParse(fit_io)
        sub_fdt = dtb.to_fdt()

    fit_io = StringIO.StringIO(signed_content)
    dtb = pyfdt.FdtBlobParse(fit_io)
    fdt = dtb.to_fdt()

    pubkey = sub_fdt.resolve_path('/images/fdt@1')
    if pubkey is None:
        print("Subordinate key store does not contain /images/fdt@1")
        sys.exit(1)

    images = fdt.resolve_path('/images')
    images.append(pubkey)
    return fdt.to_dtb()


def sign_firmware(dts):
    # Perform signing.
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(dts)
        tmp.flush()
        with tempfile.NamedTemporaryFile() as tmp2:
            print(" ".join([args.mkimage, "-f", tmp.name, "-E",
                "-k", args.keydir,
                "-p", "%08x" % args.size, "-r", tmp2.name]))
            spawn.spawn(
                [args.mkimage, "-f", tmp.name, "-E", "-k", args.keydir,
                    "-p", "%08x" % args.size, "-r", tmp2.name])
            info = os.stat(tmp2.name)
            if info.st_size <= 0:
                print("mkimage failed")
                return 1
            if info.st_size > args.max_size:
                print("mkimage generated an output U-Boot exceeding %08x" % (
                    args.max_size))
                return 1
            write_firmware(tmp2.name)
    return 0


def sign_os(dts):
    #write_content(args.os, data[args.os:])
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(dts)
        tmp.flush()
        with tempfile.NamedTemporaryFile(delete=False) as tmp2:
            print(" ".join([args.mkimage, "-f", tmp.name,
                "-k", args.keydir, "-r", tmp2.name]))
            spawn.spawn(
                [args.mkimage, "-f", tmp.name, "-k", args.keydir,
                    "-r", tmp2.name])
            info = os.stat(tmp2.name)
            if info.st_size <= 0:
                print("mkimage failed")
                return 1
            write_os(tmp2.name)
    return 0


def set_algorithms(fdt, path):
    # Override the requested hashing and signing algorithms.
    algo = fdt.resolve_path("%s/signature@1/algo" % (path))
    algo.strings = ['sha256,rsa4096']
    algo = fdt.resolve_path("%s/hash@1/algo" % (path))
    algo.strings = ['sha256']
    return 0


def set_hint(fdt, path):
    # We are not validating the FIT, but checking basic sanity.
    hint = fdt.resolve_path("%s/signature@1/key-name-hint" % (path))
    if hint is None:
        print("FIT does not include a signature node (%s)" % (path))
        return 1

    # The U-Boot FIT expects to be signed with the following key-name.
    # This will cause mkimage to file if the names do not match.
    key_name = hint[0]
    requested_key_name = os.path.basename(args.keydir)
    if key_name != requested_key_name:
        print("Note: The FIT key-name-hint (%s) does not match keydir (%s)" % (
            key_name, requested_key_name))
        hint.strings = [requested_key_name]
    return 0


def main():
    with open(args.filename) as fh:
        data = fh.read()
        # Extract the FIT describing U-Boot
        uboot_fit = data[args.offset:args.offset + args.size]

    # Represent the FIT as an IO resource.
    fit_io = StringIO.StringIO(uboot_fit)
    dtb = pyfdt.FdtBlobParse(fit_io)
    fdt = dtb.to_fdt()

    # Timestamp's existance will cause FDT_ERR_NOSPACE errors
    try:
        fdt.get_rootnode().remove('timestamp')
    except ValueError:
        # Timestamp may not be present
        pass

    # The FIT should contain /images/firmware@1
    firmware = fdt.resolve_path('/images/firmware@1')
    if firmware is None:
        print("Firmware does not contain a U-Boot FIT with /images/firmware@1")
        sys.exit(1)

    # The content of U-Boot is stored external to the FIT.
    offset = fdt.resolve_path('/images/firmware@1/data-position')
    position = int(offset[0])
    offset = fdt.resolve_path('/images/firmware@1/data-size')
    size = int(offset[0])
    if position <= 0 or size <= 0:
        print("Firmware U-Boot position is unknown /images/firmware@1")
        sys.exit(1)

    # Extract the firmware content and attach, for signing.
    uboot = data[args.offset + position:args.offset + position + size]
    new_prop = pyfdt.FdtPropertyWords.init_raw('data', uboot)
    firmware.subdata.insert(0, new_prop)

    set_algorithms(fdt, '/images/firmware@1')
    set_hint(fdt, '/images/firmware@1')

    try:
        os.remove(args.output)
    except OSError:
        pass
    write_content(0x0, data[0:args.offset])
    ret = sign_firmware(fdt.to_dts())
    if ret == 1:
        return 1

    if not args.skip_os:
        os_fit = data[args.os:]
        fit_io = StringIO.StringIO(os_fit)
        dtb = pyfdt.FdtBlobParse(fit_io)
        fdt = dtb.to_fdt()

        # Again, this node will cause FDT_ERR_NOSPACE errors
        fdt.get_rootnode().remove('timestamp')

        config = fdt.resolve_path('/configurations/conf@1')
        if config is None:
            print("OS FIT does not contain a configuration")
            return 1

        set_algorithms(fdt, '/configurations/conf@1')
        set_hint(fdt, '/configurations/conf@1')

        ret = sign_os(fdt.to_dts())
        if ret == 1:
            return 1

    print("Wrote signed firmware: %s" % (args.output))
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Example sign')
    parser.add_argument('filename', help="Input firmware")
    parser.add_argument('output', help="Output firmware")
    parser.add_argument('--offset', default=0x080000, type=int,
        help="Location within filename to find firmware FIT DTB")
    parser.add_argument('--size', default=0x4000, type=int,
        help="Size of FIT (DTB)")
    parser.add_argument('--max_size', default=0x60000, type=int,
        help="Max size of FIT and data content")
    parser.add_argument('--os', default=0xe0000, type=int,
        help="Location within filetime to find OS (kernel,rootfs) FIT DTB")
    parser.add_argument("--skip-os", default=True, action="store_true",
        help="Do not look for an OS to sign")
    parser.add_argument('--subordinate', default=None, metavar="PATH",
        help="Optional path to subordinate certificate store (to add)")
    parser.add_argument('--keydir', required=True, metavar="DIR",
        help="Required path to directory containing '.key' private key")
    parser.add_argument('--mkimage', required=True, metavar="PATH",
        help="Required path to mkimage")
    args = parser.parse_args()

    if not os.path.isdir(args.keydir):
        print("The --keydir must be a directory containing a '.key' key.")
        sys.exit(1)
    keyfile = os.path.join(args.keydir, os.path.basename(args.keydir) + ".key")
    if not os.path.exists(keyfile):
        print("Cannot find private key: %s" % (keyfile))
        sys.exit(1)

    sys.exit(main())
