"""Offline non-trading parser, heartbeat metrics and receiver lifecycle tests."""
import unittest

from pipe_probe_host import (
    HeartbeatMonitor, ProtocolViolation, parse_frame, receive_connection, serve,
)


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

    def test_partial_chunks_reassemble(self):
        monitor = HeartbeatMonitor(connected_at=10)
        self.assertEqual(monitor.feed(b"CTEA1|PI", 11), [])
        result = monitor.feed(b"NG|5|2\n", 12)
        self.assertEqual(result[0]["seq"], 5)

    def test_sequence_gap_and_clock_gap_are_recorded(self):
        monitor = HeartbeatMonitor(connected_at=10)
        monitor.feed(b"CTEA1|PING|1|0\n", 11)
        observed = monitor.feed(b"CTEA1|PING|4|0\n", 17)
        self.assertEqual(observed[0]["missing_sequences"], 2)
        self.assertEqual(observed[0]["gap_seconds"], 6)
        self.assertEqual(monitor.missing_sequences, 2)
        self.assertEqual(monitor.max_gap_s, 6)

    def test_duplicate_sequence_rejected(self):
        monitor = HeartbeatMonitor(connected_at=10)
        monitor.feed(b"CTEA1|PING|1|0\n", 11)
        with self.assertRaisesRegex(ProtocolViolation, "duplicate"):
            monitor.feed(b"CTEA1|PING|1|0\n", 12)

    def test_partial_frame_size_limited(self):
        monitor = HeartbeatMonitor(connected_at=10)
        with self.assertRaisesRegex(ProtocolViolation, "unfinished_frame"):
            monitor.feed(b"x" * 129, 12)

    def test_back_to_back_complete_frames(self):
        monitor = HeartbeatMonitor(connected_at=10)
        frames = monitor.feed(b"CTEA1|PING|1|0\nCTEA1|PING|2|1\n", 11)
        self.assertEqual([f["seq"] for f in frames], [1, 2])


class FakePipe:
    """Replay different clients without any Windows WinAPI side effects."""

    def __init__(self, sessions):
        self.sessions = sessions
        self.current = None
        self.next_index = 0
        self.closed = []
        self.accepted = []

    def new_pipe(self):
        handle = self.next_index
        self.next_index += 1
        self.current = iter(self.sessions[handle])
        return handle

    def accept(self, handle):
        self.accepted.append(handle)

    def read(self, handle, timeout):
        try:
            result = next(self.current)
        except StopIteration:
            return b""
        if isinstance(result, Exception):
            raise result
        return result

    def close_pipe(self, handle):
        self.closed.append(handle)


class PipeLifecycleTests(unittest.TestCase):
    def check_recovery(self, first_session, expected_reason):
        good = [b"CTEA1|PING|1|0\n", b""]
        pipe = FakePipe([first_session, good])
        events = []
        serve(pipe, max_clients=2, clock=lambda: 100.0,
              emit=lambda name, **d: events.append((name, d)))
        self.assertEqual(pipe.accepted, [0, 1])
        self.assertEqual(pipe.closed, [0, 1])
        ended = [d for name, d in events if name == "client_disconnected"]
        self.assertEqual([x["reason"] for x in ended], [expected_reason, "client_disconnected"])
        self.assertEqual(ended[1]["heartbeats"], 1)

    def test_invalid_frame_does_not_stop_receiver(self):
        self.check_recovery([b"bad\n"], "malformed_frame")

    def test_duplicate_frame_does_not_stop_receiver(self):
        self.check_recovery(
            [b"CTEA1|PING|1|0\n", b"CTEA1|PING|1|0\n"],
            "duplicate_or_backward_sequence",
        )

    def test_partial_frame_hang_does_not_stop_receiver(self):
        self.check_recovery([b"CTEA1|PI", TimeoutError("synthetic")], "heartbeat_deadline")

    def test_client_io_failure_does_not_stop_receiver(self):
        self.check_recovery([OSError(109, "broken pipe")], "pipe_io_error:109")

    def test_late_heartbeat_does_not_extend_deadline(self):
        events = []
        timeline = iter([0.0, 0.0, 9.0, 9.0])
        result = receive_connection(
            lambda timeout: b"CTEA1|PING|1|0\\n".replace(b"\\\\n", b"\\n"),
            clock=lambda: next(timeline), timeout_s=8.0,
            emit=lambda name, **d: events.append((name, d)),
        )
        self.assertEqual(result["reason"], "heartbeat_deadline")
        self.assertEqual(result["heartbeats"], 0)

    def test_no_initial_heartbeat_deadline(self):
        events = []
        result = receive_connection(lambda timeout: (_ for _ in ()).throw(TimeoutError()),
                                    clock=lambda: 1.0,
                                    emit=lambda name, **d: events.append((name, d)))
        self.assertEqual(result["reason"], "heartbeat_deadline")
        self.assertEqual(result["heartbeats"], 0)


if __name__ == "__main__":
    unittest.main()
