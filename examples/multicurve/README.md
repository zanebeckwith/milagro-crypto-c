# multi curves

## Quick Start

This directory contains scripts and examples that support multiple curves in 
the same executable.

In order to run the build.sh script successfully script you need to know the
MODBYTE value. This can be found by these steps;

```
./build.sh
./target/<build>/examples/amcl_build 
```

Now run ./build.sh with the correct value for example;

```
MODBYTES=48 ./build.sh
```

There are a number of example programs please see the README in the relevant directory.
