# ProtocolFuzzing

This repository contains a CAN protocol fuzzing framework for real connected CAN devices.

## Entrypoints

The command line interfaces are declared in `pyproject.toml` under `[project.scripts]`:

- `fuzz`: run a CAN-based fuzzing campaign against a real CAN device and choose the protocol with `--protocol`.
- `scan`: passively listen and actively probe a CAN bus for IDs and diagnostic responders.
- `fdcheck`: test whether the CAN adapter and target device support CAN FD.
- `plot`: generate PDF plots from campaign results.
- `clean`: remove generated files under `result` and `plot`.
- `list`: discover available CAN interfaces.

### Detect

List detected CAN interfaces:

```bash
uv run list
uv run list --json
uv run list --interfaces pcan,vector,slcan --verbose
```

Scan the CAN bus. By default, this does both passive listening and active diagnostic probing:

```bash
uv run scan --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run only one scan phase:

```bash
uv run scan --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --passive-only
uv run scan --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --active-only
```

Check CAN FD support on the hardware adapter and the target device:

```bash
uv run fdcheck --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --data-bitrate 2000000
```

### Fuzzing with CLI parameters

Run a fuzzing campaign against a real CAN interface:

```bash
uv run fuzz --protocol can --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run an upper-layer UDS fuzzing campaign:

```bash
uv run fuzz --protocol uds --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run a DBC-based fuzzing campaign:

```bash
uv run fuzz --protocol DBC --dbc_file FILE_PATH --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run an OBD-II fuzzing campaign:

```bash
uv run fuzz --protocol obd --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run a configurable private control protocol fuzzing campaign:

```bash
uv run fuzz --protocol private --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --target-ids 0x100,0x101 --opcodes 0x01,0x02,0x10
```

Examples for other python-can backends:

```bash
uv run fuzz --protocol can --interface slcan --channel COM3 --bitrate 500000
uv run fuzz --protocol can --interface vector --channel 0 --bitrate 500000
```

### Fuzzing with config file

For complex runs, put the shared defaults in a TOML file and load it with `-c`:

```bash
uv run fuzz -c config.toml
uv run fdcheck -c config.toml
uv run scan -c config.toml
```

The priority order is:

1. command line arguments
2. config file values
3. code defaults

The configuration file can use top-level shared values and per-command sections. For fuzzing, put the protocol name in the `[fuzz]` section as `protocol = "can"`, `protocol = "dbc"`, `protocol = "uds"`, `protocol = "obd"`, or `protocol = "private"`. Use the `[dbcfuzz]` section for DBC-specific overrides.

Command line options still override the config file, so you can keep the file as a base profile and adjust just one or two values per run.


### Result Analysis

Generate PDF plots from fuzzing results:

```bash
uv run plot
```

Clean generated outputs:

```bash
uv run clean
```

## Scan Outputs

- `result/can_scan_ids.csv`: observed CAN IDs, counts, DLCs, timestamps, and payload samples.
- `result/can_scan_active.csv`: active probe requests and observed responses.
- `result/can_scan_summary.json`: scan summary including unique IDs and suspected diagnostic response IDs.
- `result/can_fd_check_probes.csv`: FD probe requests and observed responses.
- `result/can_fd_check_summary.json`: FD capability summary for the adapter and target device.

## Run Options

Important hardware options:

- `--protocol`: choose `can`, `dbc`, `uds`, `obd`, or `private`.
- `--interface`: python-can backend, such as `socketcan`, `pcan`, `vector`, or `slcan`.
- `--channel`: backend-specific channel name.
- `--dbc_file`: DBC file path used when `--protocol dbc` is selected.
- `--bitrate`: arbitration bitrate. Use `none` if the selected backend does not require it.
- `--fd`: send CAN FD frames or open CAN FD mode when supported.
- `--data-bitrate`: CAN FD data bitrate.
- `--id-min` and `--id-max`: limit the fuzzing arbitration ID range.
- `--receive-timeout`: response collection window after each transmitted fuzzing frame.
- `--inter-frame-delay-ms`: delay between generated fuzzing frames.
- `--inter-request-delay-ms`: delay between protocol requests.
- `--keepalive`: send a periodic activation frame in a background thread while fuzzing.
- `--keepalive-id`, `--keepalive-payload`, `--keepalive-interval-ms`: configure the activation frame.
- `--target-ids` and `--opcodes`: private protocol target IDs and opcodes.
- `--passive-duration`: seconds to listen during scan before active probes.
- `--active-timeout`: response collection window after each active scan probe.

## DBC Support

DBC fuzzing uses the local implementation under `src/can_fuzzing/fuzzers/dbc/` and is based on the DBC parsing and CAN packing ideas from the reference copy of openDBC in `reference/opendbc`. The reference project separates DBC data, CAN parsing and packing, vehicle logic, and safety logic. This repository uses only the DBC-oriented pieces as a reference and keeps the runtime path local to the fuzzing workflow.

Reference files:

- `reference/opendbc/README.md`
- `reference/opendbc/opendbc/can/dbc.py`
- `reference/opendbc/opendbc/can/parser.py`
- `reference/opendbc/opendbc/can/packer.py`
