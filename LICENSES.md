# License

This projects is licensed under the L[LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html) license. See the license terms in [COPYING](COPYING).

## Submodules and Dependencies

This project includes several submodules and dependencies, each with its own licensing:

- `tests/machine`: Licensed under the Apache License 2.0. See the license terms in [tests/machine/LICENSE](tests/machine/LICENSE).
- `tests/uarch`: Licensed under the Apache License 2.0. Licensing details are available in [tests/uarch/LICENSE](tests/uarch/LICENSE).
- `third-party/llvm-flang-uint128`: Licensed under the Apache License 2.0 with LLVM exceptions. The license can be found at [third-party/llvm-flang-uint128/LICENSE](third-party/llvm-flang-uint128/LICENSE).
- `third-party/riscv-arch-test`: Source code licensed under the Apache 2.0 and BSD 3-Clause licenses. Documentation under `CC-BY-4.0`. License information is provided in README.md and other COPYING.* files like [third-party/riscv-arch-test/COPYING.APACHE](third-party/riscv-arch-test/COPYING.APACHE).
- `third-party/riscv-tests`: Licensed under the BSD 3-Clause "New" or "Revised" License. See [third-party/riscv-tests/LICENSE](third-party/riscv-tests/LICENSE) for license details.
- `third-party/riscv-tests/env`: Licensed under the BSD 3-Clause "New" or "Revised" License. License details are in [third-party/riscv-tests/env/LICENSE](third-party/riscv-tests/env/LICENSE).
- `third-party/tiny_sha3`: Licensed under the MIT License. The license can be found at [third-party/tiny_sha3/LICENSE](third-party/tiny_sha3/LICENSE).
- `third-party/nlohmann-json`: Licensed under the MIT License. The license can be found at [third-party/nlohmann-json/LICENSE.MIT](third-party/nlohmann-json/LICENSE.MIT).

## Debian Packages

The project releases several Debian packages, each subject to its specific licensing terms:

- `machine-emulator-[VERSION]_[ARCHITECTURE].deb` and `machine-tests-[VERSION]_[ARCHITECTURE].deb` packages are licensed under LGPL v3.0 and may include or link to other software components with different licenses.
- `machine-tests-data-[VERSION].deb`: This package contains files that are individually licensed under various terms, including but not limited to Apache-2.0, BSD-3-Clause-Regents, BSD-3-Clause, and GPL-2.0-only. For a comprehensive overview of the licenses applicable to specific files within this package, please refer to its copyright file, e.g., [tools/template/tests-data-copyright.template](tools/template/tests-data-copyright.template).

For detailed licensing information of each Debian package, please refer to the copyright file included within the package.

## Additional Notes

This project may include or link to other software components with different licenses. Contributors and users are responsible for ensuring compliance with each component's licensing terms. For detailed information, please refer to the individual LICENSE files within each directory or submodule, and for the Debian packages, please review the respective copyright and licensing details as mentioned above.
