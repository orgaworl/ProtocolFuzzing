# ProtocolFuzzing

This repository contains a CAN protocol fuzzing framework for real connected CAN devices.

## Entrypoints

The command line interfaces are declared in `pyproject.toml` under `[project.scripts]`:

- `fuzz`: run a CAN fuzzing campaign against a real CAN device.
- `plot`: generate PDF plots from campaign results.
- `clean`: remove generated files under `result` and `plot`.
- `list`: discover available CAN interfaces.

Run a fuzzing campaign against a real CAN interface:

```bash
uv run fuzz --interface socketcan --channel can0 --bitrate 500000 --cases 1000 --seed 1337
```

Examples for other python-can backends:

```bash
uv run fuzz --interface pcan --channel PCAN_USBBUS1 --bitrate 500000
uv run fuzz --interface slcan --channel COM3 --bitrate 500000
uv run fuzz --interface vector --channel 0 --bitrate 500000
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

## Run Options

Important hardware options:

- `--interface`: python-can backend, such as `socketcan`, `pcan`, `vector`, or `slcan`.
- `--channel`: backend-specific channel name.
- `--bitrate`: arbitration bitrate. Use `none` if the selected backend does not require it.
- `--fd`: send CAN FD frames.
- `--data-bitrate`: CAN FD data bitrate.
- `--id-min` and `--id-max`: limit the arbitration ID range.
- `--receive-timeout`: response collection window after each transmitted frame.
- `--inter-frame-delay-ms`: delay between generated frames.





