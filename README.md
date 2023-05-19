# AdGuard VPN libs

A VPN client library that provides client network traffic tunnelling to an AdGuard VPN server.

## Build instructions

### Prerequisites

* CMake 3.7 or higher
* Clang 8 or higher
* Conan 1.38 or higher

### Building

If it is a clean build, export custom conan packages to the local conan repository.
See https://github.com/AdguardTeam/NativeLibsCommon/blob/master/README.md for details.

To build the main library:
```
mkdir build && cd build
cmake ..
make vpnlibs_core
```

To run tests:
```
make tests && ctest
```

To build a minimal working example application, run:
```
make standalone_client
```
Refer to `core/test/standalone_client/README.md`

## Project structure

Every subproject consists of the following directories and files:
- `include/<module_name>/` - public headers (add the `include` directory to includes only, so that include header
from other module would look like `#include "module/header.h"`)
- `include/<module_name>/internal` - not so public headers (they are not part of the public API,
but may be needed by other modules, or to extend the library)
- `src/` - source code files and private headers
- `test/` - tests and their data
- `CMakeLists.txt` - cmake build config

Root project consists of the following directories and files:
- `common/` - Set of useful general-purpose utilities
- `core/` - VPN client core module (configuration, traffic tunnelling, etc.)
- `net/` - network communication
- `tcpip/` - L3 and L4 protocols handling (the network and transport layers)
- `third-party/` - third-party libraries (this is not a subproject, so subproject's rules are not enforced)
- `CMakeLists.txt` - main cmake build config.

The public API is in `core/include/vpn.h`.

## Testing changes as a dependency

To test local changes in the library in case it is used as a conan package dependency,
do the following:

1) Create patch files: e.g., execute `git diff > 1.patch` in the project root.
2) Add paths to the patch files in `<root>/conanfile.py`, see the `patch_files` field.
3) Change the `vcs_url` field in `<root>/conanfile.py` if the default one is not suitable.
4) Export the conan package with the special version number: `conan export . /777@AdguardTeam/NativeLibsCommon`.
5) In the project that uses `vpn-libs` as a dependency, change the version to `777`
   (e.g. `vpn-libs/1.0.0@AdguardTeam/NativeLibsCommon` -> `vpn-libs/777@AdguardTeam/NativeLibsCommon`).
6) Re-run cmake command.  
   Notes:
     * if one has already exported vpn-libs in such way, the cached version must be purged: `conan remove -f vpn-libs/777`,
     * by default the patches are applied to the `master` branch, specify the `commit_hash` option to test changes against the specific commit.

## License

Copyright (C) AdGuard Software Ltd.

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
