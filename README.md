# pyflib

Locate code from .o files inside a binary file.

This works by looking for the text bytes from the functions in the input .o files inside the input binary file, ignoring the bytes affected by relocations.

Setup:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Run tests:

```sh
export IDO7RECOMP=~/Documents/oot/tools/ido_recomp/linux/7.1/cc
./testbuild.sh
python3 find_o.py --test
```

Example run:

```sh
python3 find_o.py ~/Documents/oot/extracted/ntsc-1.0/baserom/n64dd ~/Documents/n64data/leo_collection/byhash/extracted/*/*.o | tee out.txt
```
