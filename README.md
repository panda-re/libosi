<h1 align="center">:construction: Libosi :construction:</h1>

Operating System Introspection library to support PANDA.

### Prerequisites

Install dependencies. On Ubuntu, this can be done with:

```bash
sudo apt-get update

sudo apt-get install cmake ninja-build rapidjson-dev
```

### Building

To build libosi, from the root of this repo run:

```bash
mkdir build && cd $_
cmake -GNinja ..
ninja
```

### Installing

Installing libosi includes running:

```bash
cd build && ninja package
sudo dpkg -i libosi-[version].deb
```

### Testing

Testing is currently implemented for offset and iohal. To run the tests, you will 
first need to install `libgtest-dev` and enable testing:

```bash
sudo apt-get install libgtest-dev

cd build
cmake -GNinja -DENABLE_TESTING=ON ..
ninja
```

You can then run the tests with just `ninja test`.

### Style

Currently, the code is formatted with clang-format, using the style provided in `.clang-format`.

### Development

This library currently supports Windows 7 and Debian 8.11 (linux kernel v3.16).
Support for similar Windows and Linux kernels is as simple as adding a new profile to `src/offset/profiles`.
However, in some kernels, struct names may have changed. In these cases, you may need to add/port
API functions in `src/osi/windows/api.cc`, where these names are assumed.

Support is currently limited to i386 and amd64. Support for more architectures includes writing
a new translator within `src/iohal/translators`.

Pull Requests are welcome.

#### To-Do

:pushpin: Support pointers to pointers in offset  
:pushpin: Offset should have something like a sizeof() function to better support arrays  
:pushpin: Load offsets from disk, rather than having a large dictionary which needs to be compiled   
:pushpin: Find a place to host memory snapshots for wintrospection tests  
:pushpin: Include tools and documentation for generating new profiles  
:pushpin: Run cpp-check over the code before every commit  
