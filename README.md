<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-transport-tcp

First-party signed kind:transport plugin cdylib: the tcp transport, packaged as a droppable busbar plugin. Drop the signed tarball into plugins/ and the boot seal folds the wire beside the linked ones.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `transport` | `tcp` | `busbar-transport-tcp-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

<!-- fleet:header:end -->

## What it is for

`busbar-transport-tcp` is a `kind: transport` busbar plugin.

## Config

Configured under the `tcp` module name. It takes no settings: empty settings mean `{}`, and any
key, `null` or non-object is refused (see `transport-tcp/settings.schema.json`).

## Connection cleanup

If host I/O cannot close a connection, `shut` reports the failure and retains the connection for a later close attempt. A close the host refuses because it no longer holds the handle (it already released it, or took the socket off its table) is reported but leaves nothing to retry, so the connection is forgotten. The same rule applies when `flush` finds that a dial failed to connect: the carrier closes the
connection, and keeps it for a later `shut` only if the host could not close a handle it still
holds. Successful closes and closing an unknown connection remain idempotent.

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
