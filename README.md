<!-- fleet:header:begin (rendered by `cargo xtask fleet render` from GetBusbar/busbar's plugins.yaml; edit it there) -->
# busbar-transport-tcp

First-party signed kind:transport plugin cdylib: the tcp transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and the boot seal folds the wire beside the linked ones.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `tcp` | `busbar-transport-tcp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-transport-tcp/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-transport-tcp/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

`busbar-transport-tcp` is a `kind: transport` busbar plugin.

## Config

Configured under the `tcp` module name.

## Build

```bash
cargo build --release -p busbar-transport-tcp-plugin
```

## Tests

```bash
cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
