"""Offline parser tests for the read-only MT5 pipe probe."""
import unittest

from pipe_probe_host import parse_frame


class ProbeProtocolTests(unittest.TestCase):
    def test_valid_probe(self):
        self.assertEqual(parse_frame(b"CTEA1|PING|123|7\n"), (123, 7))

    def test_rejects_order_injection(self):
        self.assertIsNone(parse_frame(b"CTEA1|ORDER|123|7\n"))

    def test_rejects_non_numeric(self):
        self.assertIsNone(parse_frame(b"CTEA1|PING|1;BUY|7\n"))

    def test_requires_newline(self):
        self.assertIsNone(parse_frame(b"CTEA1|PING|123|7"))

    def test_bounded_frame(self):
        self.assertIsNone(parse_frame(b"CTEA1|PING|" + b"9" * 200 + b"|0\n"))

    def test_rejects_trailing_garbage(self):
        self.assertIsNone(parse_frame(b"CTEA1|PING|1|0\nORDER"))

    def test_rejects_empty(self):
        self.assertIsNone(parse_frame(b""))


if __name__ == "__main__":
    unittest.main()
