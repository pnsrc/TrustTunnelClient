# Standalone VPN client

## Configuration

Use the [setup_wizard](./setup_wizard) for the guided client configuration.

It is executed automatically as a dependency for the `standalone_client` client.
To run it manually, execute the following commands in the Terminal:

```shell
cd <path/to/standalone_client>/setup_wizard
cargo run --bin setup_wizard
```

## Command line arguments

To select a configuration file other than the default one, pass its name in the command line arguments:

    --config=FILENAME, -c FILENAME

You can also override some parameters from the configuration file through the command line, for example:

* The logging level: `--loglevel=LOGGING_LEVEL, -l LOGGING_LEVEL`,
* Skip certificate verification: `-s`.

To see the full set of available options, run it with `--help`.
