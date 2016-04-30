## FIT Certificate Store

This is a Firmware Image Tree (FIT) certificate store generator.

### Dependencies

- `dtc` - the device tree compiler
- A public RSA key

Python will need `jinja2`, `argparse` and `Crypto`.

### Usage

```bash
python ./fit-cs.py --help

```

Try the tests:
```
python ./fit-cs.py ./tests > /tmp/test.dts
diff ./tests/dev.dts /tmp/test.dts
```
