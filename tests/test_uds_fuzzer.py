from __future__ import annotations

import random
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from can_fuzzing.fuzzing.uds_fuzz import UDSFuzzConfig, build_request


class UDSFuzzerTests(unittest.TestCase):
    def test_malformed_service_choice_accepts_tuple_dictionary(self) -> None:
        config = UDSFuzzConfig(malformed_rate=1.0)
        rng = random.Random(7)
        request = build_request(rng, config)
        self.assertTrue(request.is_malformed)
        self.assertGreaterEqual(request.service_id, 0)
        self.assertLessEqual(request.service_id, 0xFF)


if __name__ == "__main__":
    unittest.main()



