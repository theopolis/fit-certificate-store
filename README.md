## FIT Certificate Store

This is a Firmware Image Tree (FIT) certificate store generator.

### Dependencies

- `dtc` - the device tree compiler
- A public RSA key

Python will need `jinja2`, `argparse` and `Crypto`.

### Usage

```bash
python ./fit-cs.py --help
usage: fit-cs.py [-h] [--ext pub] [--template PATH] [--no-out]
                 [--algorithm sha256] [--required-node conf]
                 DIRECTORY [OUTPUT_DTB]

Generate a FIT certificate store (a DTB).

positional arguments:
  DIRECTORY             Path to directory containing public keys
  OUTPUT_DTB            Output path of compiled certificate store (dtb)

optional arguments:
  -h, --help            show this help message and exit
  --ext pub             Search for public keys with this file extension
  --template PATH       Certificate store template
  --no-out              Print the resultant source instead of compiling
  --algorithm sha256    Override default hashing algorithm
  --required-node conf  Set the required node (default=conf)
```

Try the tests:
```
python ./fit-cs.py --no-out ./tests > /tmp/test.dts
diff ./tests/dev.dts /tmp/test.dts
```
