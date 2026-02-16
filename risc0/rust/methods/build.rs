// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

fn main() {
    use std::collections::HashMap;
    use std::path::PathBuf;

    println!("cargo:rerun-if-env-changed=RISC0_USE_DOCKER");

    // Use Docker by default for reproducible builds (same Image ID on all platforms).
    // Set RISC0_USE_DOCKER=0 for environments without Docker (e.g., RunPod containers).
    // Native builds produce a platform-specific Image ID that differs from the canonical one.
    let use_docker = std::env::var("RISC0_USE_DOCKER")
        .map(|v| v != "0")
        .unwrap_or(true);

    if use_docker {
        // Docker context must be the repo root so the guest build.rs
        // can access risc0/cpp/risc0-replay-steps.o via relative path.
        // CARGO_MANIFEST_DIR = .../risc0/rust/methods, so go up 3 levels.
        let root_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("../../..")
            .canonicalize()
            .unwrap();

        let docker_opts = risc0_build::DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .build()
            .unwrap();

        let guest_opts = risc0_build::GuestOptionsBuilder::default()
            .use_docker(docker_opts)
            .build()
            .unwrap();

        risc0_build::embed_methods_with_options(HashMap::from([
            ("replay_step", guest_opts),
        ]));
    } else {
        risc0_build::embed_methods_with_options(HashMap::new());
    }
}
