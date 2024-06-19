# ebpf_objdump

The implementation is based on the [Linux kernel v6.9 document](https://www.kernel.org/doc/html/v6.9/bpf/standardization/instruction-set.html).

## Usage
> [!IMPORTANT]
> This project is developed on a Docker container, which can be created with [this Dockerfile](https://github.com/offnaria/llvm-18.1.6_dockerfile/tree/84df944ce1f739609ee450fbfb765135bf98c13e).

Build libbpf at first.
```
git submodule update --init --recursive
cd submodule/libbpf/src
make
```

If you don't have `pkg-config`, add `NO_PKG_CONFIG=1` option when you type `make`.

Then, build `ebpf_objdump`.
```
# cd ../../..
make
```

Now you can use `ebpf_objdump`.
```
./build/ebpf_objdump <eBPF object file>
```

## License
SPDX-License-Identifier: MIT
See [LICENSE](LICENSE).
