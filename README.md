<h1 align="center">System Introspection</h1>

:pushpin: What's a more catchy name?

Standalone System Introspection library.

:warning: This repo is a work in progress!

### Prerequisites

Install dependencies. On Ubuntu, this can be done with:

```bash
apt-get update

apt-get install cmake ninja-build rapidjson-dev
```

### Building

To build wintrospection, from the root of this repo run:

```bash
mkdir build && cd $_
cmake -GNinja ..
ninja
```

### Development

This library currently supports Windows 7 and Debian 8.11 (linux kernel v3.16).
Support for similar Windows and Linux kernels is as simple as adding a new profile to `offset`.
