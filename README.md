<h1 align="center">:construction: Libosi :construction:</h1>

Operating System Introspection library to support PANDA.

### Prerequisites

Install dependencies. On Ubuntu, this can be done with:

```bash
apt-get update

apt-get install cmake ninja-build rapidjson-dev
```

### Building

To build libosi, from the root of this repo run:

```bash
mkdir build && cd $_
cmake -GNinja ..
ninja
```

### Development

This library currently supports Windows 7 and Debian 8.11 (linux kernel v3.16).
Support for similar Windows and Linux kernels is as simple as adding a new profile to `src/offset/profiles`.
If the kernel has significantly changed since the supported version, API functions may need to be added/ported.

Support is currently limited to i386 and amd64. Support for more architectures includes writing
a new translator within `src/iohal/translators`.

Pull Requests are welcome.

### To-Do

:pushpin: Support pointers to pointers in offset  
:pushpin: Offset should have something like a sizeof() function to better support arrays  
:pushpin: Find a place to host memory snapshots for wintrospection tests  
:pushpin: Include tools and documentation for generating new profiles.  
:pushpin: Load offsets from disk, rather than having a large dictionary which needs to be compiled   
