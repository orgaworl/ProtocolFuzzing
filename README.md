# ProtocolFuzzing

This repository contains a CAN protocol fuzzing framework for real connected CAN devices.

## Entrypoints

The command line interfaces are declared in `pyproject.toml` under `[project.scripts]`:

- `fuzz`: run a CAN fuzzing campaign against a real CAN device.
- `scan`: passively listen and actively probe a CAN bus for IDs and diagnostic responders.
- `fdcheck`: test whether the CAN adapter and target device support CAN FD.
- `plot`: generate PDF plots from campaign results.
- `clean`: remove generated files under `result` and `plot`.
- `list`: discover available CAN interfaces.

Run a fuzzing campaign against a real CAN interface:

```bash
uv run fuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
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

Examples for other python-can backends:

```bash
uv run fuzz --interface slcan --channel COM3 --bitrate 500000
uv run fuzz --interface vector --channel 0 --bitrate 500000
```

Generate PDF plots from fuzzing results:

```bash
uv run plot
```

Clean generated outputs:

```bash
uv run clean
```

List detected CAN interfaces:

```bash
uv run list
uv run list --json
uv run list --interfaces pcan,vector,slcan --verbose
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
- `--passive-duration`: seconds to listen during scan before active probes.
- `--active-timeout`: response collection window after each active scan probe.
