"""Independent protocol reference tests; these do not prove Android behavior."""
import json
from pathlib import Path
import struct
import unittest
from cryptography.exceptions import InvalidTag
from linux_client import Codec, checksum


class WireReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((Path(__file__).parent/'vectors.json').read_text())
        cls.key = bytes.fromhex(cls.fixtures['psk_hex'])
        cls.sid = int(cls.fixtures['vectors'][0]['session_id_hex'], 16)

    def test_independent_fixed_vectors(self):
        client = Codec(self.key, self.sid)
        for vector in self.fixtures['vectors']:
            frame = bytes.fromhex(vector['frame_hex'])
            plain = bytes.fromhex(vector['plaintext_hex'])
            if vector['direction'] == 0:
                self.assertEqual(client.encode(vector['kind'], plain), frame)
            else:
                self.assertEqual(client.decode(frame), (vector['kind'], plain))

    def test_reflected_kernel_echo_rejected(self):
        codec = Codec(self.key, self.sid)
        with self.assertRaises(InvalidTag):
            codec.decode(codec.encode(2))
        self.assertEqual((codec.high, bytes(codec.seen)), (0, bytes(codec.replay_window)))

    def test_header_ciphertext_and_tag_tamper_rejected(self):
        original = bytes.fromhex(self.fixtures['vectors'][1]['frame_hex'])
        for index in range(len(original)):
            codec = Codec(self.key, self.sid)
            changed = bytearray(original)
            changed[index] ^= 1
            with self.assertRaises((ValueError, InvalidTag)):
                codec.decode(bytes(changed))
            self.assertEqual((codec.high, bytes(codec.seen)), (0, bytes(codec.replay_window)))

    def test_duplicate_rejected(self):
        codec = Codec(self.key, self.sid)
        frame = bytes.fromhex(self.fixtures['vectors'][1]['frame_hex'])
        codec.decode(frame)
        with self.assertRaises(ValueError):
            codec.decode(frame)

    def test_length_and_trailing_data_rejected(self):
        frame = bytes.fromhex(self.fixtures['vectors'][1]['frame_hex'])
        for invalid in [frame[:-1], frame+b'x', b'', frame[:24]]:
            with self.assertRaises(ValueError):
                Codec(self.key, self.sid).decode(invalid)

    def test_icmp_checksum_even_and_odd_payload(self):
        for payload in [b'EVEN', b'ODD']:
            packet = struct.pack('!BBHHH', 8, 0, 0, 100, 1) + payload
            packet = packet[:2]+struct.pack('!H', checksum(packet))+packet[4:]
            self.assertEqual(checksum(packet), 0)
            changed = bytearray(packet)
            changed[-1] ^= 1
            self.assertNotEqual(checksum(bytes(changed)), 0)


if __name__ == '__main__':
    unittest.main()
