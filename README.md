# ProtocolFuzzing

This repository contains a CAN protocol fuzzing framework for real connected CAN devices.

## Entrypoints

The command line interfaces are declared in `pyproject.toml` under `[project.scripts]`:

- `fuzz`: run a CAN fuzzing campaign against a real CAN device.
- `udsfuzz`: run a UDS / ISO-TP fuzzing campaign on top of CAN.
- `obdfuzz`: run an OBD-II fuzzing campaign on top of CAN.
- `privatefuzz`: run a configurable private control protocol fuzzing campaign on top of CAN.
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
uv run fuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run an upper-layer UDS fuzzing campaign:

```bash
uv run udsfuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run an OBD-II fuzzing campaign:

```bash
uv run obdfuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
```

Run a configurable private control protocol fuzzing campaign:

```bash
uv run privatefuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000 --target-ids 0x100,0x101 --opcodes 0x01,0x02,0x10
```

Examples for other python-can backends:

```bash
uv run fuzz --interface slcan --channel COM3 --bitrate 500000
uv run fuzz --interface vector --channel 0 --bitrate 500000
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

The configuration file can use top-level shared values and per-command sections. A single `config.toml` can therefore hold settings for multiple entrypoints:

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

- `--interface`: python-can backend, such as `socketcan`, `pcan`, `vector`, or `slcan`.
- `--channel`: backend-specific channel name.
- `--bitrate`: arbitration bitrate. Use `none` if the selected backend does not require it.
- `--fd`: send CAN FD frames or open CAN FD mode when supported.
- `--data-bitrate`: CAN FD data bitrate.
- `--id-min` and `--id-max`: limit the fuzzing arbitration ID range.
- `--receive-timeout`: response collection window after each transmitted fuzzing frame.
- `--inter-frame-delay-ms`: delay between generated fuzzing frames.
- `--keepalive`: send a periodic activation frame in a background thread while fuzzing.
- `--keepalive-id`, `--keepalive-payload`, `--keepalive-interval-ms`: configure the activation frame.
- `udsfuzz` targets UDS / ISO-TP requests and keeps the CAN frame layer separate from the lower-level `fuzz` command.
- `obdfuzz` targets OBD-II modes and PIDs over CAN and is separate from both `fuzz` and `udsfuzz`.
- `privatefuzz` targets configurable private control IDs and opcodes over CAN and records target, opcode, payload strategy, and responses.
- `--passive-duration`: seconds to listen during scan before active probes.
- `--active-timeout`: response collection window after each active scan probe.
