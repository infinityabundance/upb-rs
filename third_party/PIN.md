# Upstream protobuf / upb pin record

This directory contains a partial-clone (`--filter=blob:none`) of
`protocolbuffers/protobuf` checked out at the commit below. It is the Tier-1
behavioral oracle for upb-rs (see forensics/SOURCE_BASELINE.md §Tier hierarchy).

## Pin

| Field            | Value                                                        |
|------------------|--------------------------------------------------------------|
| repository       | https://github.com/protocolbuffers/protobuf.git              |
| commit SHA       | `2de70d710510ea7c5ad7ec0c72bfed7f411c7b60`                   |
| describe         | `v36-dev-400-g2de70d710`                                     |
| version.json     | `37-dev` (rust `0.37-dev`, protoc `37-dev`)                  |
| commit subject   | "Add allocation failure tests for unknowns and defbuilder"   |
| commit date      | 2026-08-19 13:44:36 -0700                                    |
| checkout mode    | detached HEAD, partial clone (`--filter=blob:none`)          |

## Why this commit

This is the current upstream HEAD at the time upb-rs was started
(2026-08-19). The oracle is pinned to a single commit so that every
differential receipt is reproducible against a fixed upstream.

## Version upgrade workflow

When a new upstream release appears, run the procedure in
forensics/OPEN_QUESTIONS.md §"Continuous upstream differential tracking"
(also §50 of the project charter):

1. record the old and new SHAs in this file,
2. build the new oracle,
3. regenerate the atlases,
4. rerun all courts,
5. classify behavior changes,
6. create migration casefiles.

## Build provenance (initial oracle build)

Recorded in receipts/ after the first successful oracle build. Rebuild with:

    cmake -S third_party/protobuf -B third_party/build \
      -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC=OFF \
      -Dprotobuf_BUILD_SHARED_LIBS=OFF
    cmake --build third_party/build --target upb -j

See tools/oracle/README.md for the exact oracle build and invocation.
