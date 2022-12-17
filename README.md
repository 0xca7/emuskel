# emuskel

a "skeleton" unicorn aarch64 emulator implementation, my template for emulation projects in Rust.

*see `python3/` for the same thing in python3, mind the top comment at in the source code file for an excellent resource regarding unicorn emulator in python*

This serves as:

- a baseline for me if I need an emulator
- instead of starting from scratch this project already has a basic emulation setup

It contains:

- the module `conf` lets you read the configuration of the emulator from a file
- the module `emulator` realized encapsulation of unicorn routines, hooks etc.
- the module `trace` allows tracing all executed instructions
- `skel` is a skeleton application that uses all of the above modules

thanks to the unicorn emulator devs for making this awesome software.

#### 0xca7