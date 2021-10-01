<h1 align="center">:construction: System Introspection :construction:</h1>

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

### To-Do

:pushpin: Is there a more catchy name for this?  
:pushpin: Is there a better way to reduce the duplication of translate functions in offset?  
:pushpin: Support structs that aren't kernel types, such as \_FILE\_RENAME\_INFORMATION  
:pushpin: Support pointers to pointers in offset  
:pushpin: Offset should have something like a sizeof() function to better support arrays  
