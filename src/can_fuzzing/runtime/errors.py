from __future__ import annotations


class CANConnectionError(RuntimeError):
    pass


def build_unknown_channel_message(interface: str, channel: str) -> str:
    lines = [f"Unknown CAN channel {channel!r} for interface {interface!r}."]
    if interface == "pcan" and channel.startswith("PCAN-"):
        lines.append("PCAN channel names use underscores, not hyphens. Did you mean PCAN_USBBUS1?")
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def build_can_error_message(interface: str, channel: str, exc: Exception) -> str:
    lines = [
        f"Could not open CAN interface {interface!r} channel {channel!r}.",
        f"Backend error: {exc}",
    ]
    lines.extend(channel_status_hint(interface, channel))
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def build_os_error_message(interface: str, channel: str, exc: OSError) -> str:
    lines = [
        f"Could not open CAN interface {interface!r} channel {channel!r}.",
        f"OS error: {exc}",
    ]
    if interface == "socketcan":
        lines.append("SocketCAN is normally available on Linux. On Windows, use a backend such as pcan, vector, or slcan.")
    lines.extend(discovery_hint(interface))
    return "\n".join(lines)


def discovery_hint(interface: str) -> list[str]:
    lines = ["Run uv run list to see detected CAN interfaces."]
    try:
        from ..scanning.hardware_scan import list_can_interfaces

        configs = list_can_interfaces(interfaces=[interface], include_virtual=False, verbose=False)
    except RuntimeError:
        return lines
    if configs:
        channels = ", ".join(str(config.get("channel", "")) for config in configs)
        lines.append(f"Detected {interface} channel(s): {channels}")
    return lines


def channel_status_hint(interface: str, channel: str) -> list[str]:
    if interface != "pcan":
        return []
    try:
        from ..scanning.hardware_scan import list_can_interfaces

        configs = list_can_interfaces(interfaces=[interface], include_virtual=False, verbose=False)
    except RuntimeError:
        return ["For PCAN-USB, check that PCAN-View or another PCAN client is not using the channel."]
    for config in configs:
        if str(config.get("channel", "")) != channel:
            continue
        condition = config.get("channel_condition")
        if condition == 0:
            return ["The PCAN channel is unavailable."]
        if condition == 1:
            return ["The PCAN channel is available, but opening still failed. Check the PCAN driver and channel parameters."]
        if condition == 2:
            return ["The PCAN channel is occupied by another client."]
        if condition == 3:
            return ["The PCAN channel is occupied by PCAN-View or another PCAN client."]
        return [f"The PCAN channel reported condition {condition}."]
    return ["For PCAN-USB, check that PCAN-View or another PCAN client is not using the channel."]
