from __future__ import annotations

import sys
from pathlib import Path
from types import ModuleType
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from can_fuzzing.runtime.adapters import CANHardwareAdapter
from can_fuzzing.runtime.models import CANFrame, FrameFormat, FrameType


class DummyMessage:
    def __init__(self, arbitration_id: int, data: bytes, is_rx: bool = True, is_fd: bool = False) -> None:
        self.arbitration_id = arbitration_id
        self.data = data
        self.is_rx = is_rx
        self.is_fd = is_fd
        self.is_extended_id = False
        self.is_remote_frame = False
        self.is_error_frame = False


class DummyBus:
    def __init__(self, responses_after_send: list[DummyMessage]) -> None:
        self.responses_after_send = responses_after_send
        self.sent_messages: list[DummyMessage] = []
        self.sent = False

    def send(self, message) -> None:
        self.sent_messages.append(message)
        self.sent = True

    def recv(self, timeout: float):
        if self.sent and self.responses_after_send:
            return self.responses_after_send.pop(0)
        return None

    def shutdown(self) -> None:
        return None



class ProbeBus(DummyBus):
    def recv(self, timeout: float):
        if self.responses_after_send:
            return self.responses_after_send.pop(0)
        return None


def install_fake_can_module(bus_factory=None) -> None:
    module = ModuleType('can')

    class FakeCanError(Exception):
        pass

    class FakeMessage:
        def __init__(self, **kwargs) -> None:
            self.arbitration_id = kwargs.get('arbitration_id')
            self.data = bytes(kwargs.get('data', b''))
            self.is_extended_id = kwargs.get('is_extended_id', False)
            self.is_remote_frame = kwargs.get('is_remote_frame', False)
            self.is_error_frame = kwargs.get('is_error_frame', False)
            self.is_fd = kwargs.get('is_fd', False)
            self.check = kwargs.get('check', True)

    module.CanError = FakeCanError
    module.Message = FakeMessage
    module.interface = ModuleType('can.interface')
    module.interface.Bus = bus_factory or (lambda **kwargs: None)
    sys.modules['can'] = module


class AdapterEchoTests(unittest.TestCase):
    def setUp(self) -> None:
        install_fake_can_module()


    def test_auto_bitrate_selects_candidate_with_observed_traffic(self) -> None:
        opened: list[dict] = []

        def bus_factory(**kwargs):
            opened.append(kwargs)
            bitrate = kwargs.get('bitrate')
            responses = []
            if bitrate == 500000:
                responses = [DummyMessage(0x123, b'\x01\x02')]
            return ProbeBus(responses)

        install_fake_can_module(bus_factory)
        adapter = CANHardwareAdapter(
            'pcan',
            'PCAN_USBBUS1',
            bitrate=None,
            auto_bitrate=True,
            bitrate_candidates=(125000, 500000),
            bitrate_probe_timeout=0.001,
        )

        with adapter:
            self.assertEqual(adapter.detected_bitrate, 500000)
            self.assertEqual(adapter.auto_bitrate_status, 'detected_from_bus_traffic')

        self.assertEqual([item.get('bitrate') for item in opened], [125000, 500000])

    def test_transact_drops_echo_message(self) -> None:
        adapter = CANHardwareAdapter('pcan', 'PCAN_USBBUS1', receive_timeout=0.001, drop_echo=True)
        echo = DummyMessage(0x7DF, b'\x02\x3e\x00\x00\x00\x00\x00\x00')
        response = DummyMessage(0x7E8, b'\x03\x7f\x3e\x11\x00\x00\x00\x00')
        adapter._bus = DummyBus([echo, response])

        frame = CANFrame.from_ints(0x7DF, [0x02, 0x3E, 0x00, 0, 0, 0, 0, 0], FrameFormat.STANDARD, FrameType.DATA)
        observation = adapter.transact(frame)

        self.assertTrue(observation.sent)
        self.assertFalse(observation.fault)
        self.assertEqual(observation.response_count, 1)
        self.assertEqual(observation.response_ids, [0x7E8])
        self.assertEqual(observation.response_payloads, ['037f3e1100000000'])

    def test_transact_can_keep_echo_when_disabled(self) -> None:
        adapter = CANHardwareAdapter('pcan', 'PCAN_USBBUS1', receive_timeout=0.001, drop_echo=False)
        echo = DummyMessage(0x7DF, b'\x02\x3e\x00\x00\x00\x00\x00\x00')
        adapter._bus = DummyBus([echo])

        frame = CANFrame.from_ints(0x7DF, [0x02, 0x3E, 0x00, 0, 0, 0, 0, 0], FrameFormat.STANDARD, FrameType.DATA)
        observation = adapter.transact(frame)

        self.assertEqual(observation.response_count, 1)
        self.assertEqual(observation.response_ids, [0x7DF])
        self.assertEqual(observation.response_payloads, ['023e000000000000'])


if __name__ == '__main__':
    unittest.main()


