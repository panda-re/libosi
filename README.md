<h1 align="center">Wintrospection</h1>

Windows introspection library.

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
