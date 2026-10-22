"""Check the v2 broadcaster's signature layout, counter, and framing.

Mirrors esp32_ble_nonce_sign_frag.ino. Does not exercise BLE or flash.
"""

from nacl.signing import SigningKey

AD_START, AD_MIDDLE, AD_END = 0xDD, 0xDE, 0xDF
PROTO_VERSION = 2
FLAG_CHECK_COUNTER = 0x01
NONCE_SIZE = 32
SIG_SIZE = 64
DATA_FRAME_SIZE = 26
ANNOUNCE_DATA_SIZE = 24
COUNTER_RESERVE = 8192
EXAMPLE_SEED_HEX = "1032547698BADCFE0123456789ABCDEF55AA11EE22DD33CC44BB6699778800FF"


def crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ 0x31) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def parse_seed_hex(hex_text: str) -> bytes:
    if len(hex_text) != 64:
        raise ValueError("seed must be 64 hex characters")
    return bytes.fromhex(hex_text)


def build_body(counter: int, challenge: bytes, nonce: bytes, seed: bytes, check: bool) -> bytes:
    flags = FLAG_CHECK_COUNTER if check else 0
    message = bytes([
        flags,
        (counter >> 24) & 0xFF,
        (counter >> 16) & 0xFF,
        (counter >> 8) & 0xFF,
        counter & 0xFF,
        len(challenge),
    ]) + challenge + nonce
    signature = SigningKey(seed).sign(message).signature
    if len(signature) != SIG_SIZE:
        raise AssertionError("signature length")
    return message + signature


def chunk_count(body_len: int) -> int:
    return (body_len + DATA_FRAME_SIZE - 1) // DATA_FRAME_SIZE


def assign_base(global_seq: int, total_frames: int) -> tuple[int, int]:
    if global_seq + total_frames > 65535:
        global_seq = 0
    base = global_seq
    return base, (global_seq + total_frames) & 0xFFFF


def build_adv(ad_type: int, seq: int, data: bytes) -> bytes:
    crc_input = bytes([(seq >> 8) & 0xFF, seq & 0xFF]) + data
    crc = crc8(crc_input)
    length = len(crc_input) + 2
    raw = bytes([length, ad_type]) + crc_input + bytes([crc])
    if len(raw) > 31:
        raise AssertionError(f"frame is {len(raw)} bytes")
    if raw[0] != len(raw) - 1:
        raise AssertionError("BLE length field")
    return raw


def fragment(body: bytes, global_seq: int, flags: int, challenge_len: int) -> tuple[list[bytes], int]:
    chunks = chunk_count(len(body))
    total = 1 + chunks
    base, next_seq = assign_base(global_seq, total)
    meta = bytearray(ANNOUNCE_DATA_SIZE)
    meta[0] = (len(body) >> 8) & 0xFF
    meta[1] = len(body) & 0xFF
    meta[2] = chunks
    meta[3] = PROTO_VERSION
    meta[4] = flags
    meta[5] = challenge_len
    frames = [build_adv(AD_START, base, bytes(meta))]
    for index in range(chunks):
        offset = index * DATA_FRAME_SIZE
        piece = body[offset:offset + DATA_FRAME_SIZE]
        frame_index = index + 1
        ad_type = AD_END if frame_index == total - 1 else AD_MIDDLE
        frames.append(build_adv(ad_type, (base + frame_index) & 0xFFFF, piece))
    return frames, next_seq


def check_crc(frame: bytes) -> None:
    content = frame[1:-1]
    if crc8(content[1:]) != frame[-1]:
        raise AssertionError("CRC mismatch")


def reassemble(frames: bytes | list[bytes]) -> bytes:
    body = b""
    for frame in frames[1:]:
        # length, type, seq_hi, seq_lo, data..., crc
        data_len = frame[0] - 4
        body += frame[4:4 + data_len]
    return body


def test_crc_matches_firmware_shift() -> None:
    # 0x80: first shift is (0x100 ^ 0x31) truncated to 0x31, then seven more bits end at 0x7A.
    if crc8(b"\x80") != 0x7A:
        raise AssertionError(hex(crc8(b"\x80")))
    if crc8(b"") != 0 or crc8(b"\x00") != 0:
        raise AssertionError("zero crc")


def test_seed_and_signature() -> None:
    seed = parse_seed_hex(EXAMPLE_SEED_HEX)
    expected = bytes([
        0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x55, 0xAA, 0x11, 0xEE, 0x22, 0xDD, 0x33, 0xCC,
        0x44, 0xBB, 0x66, 0x99, 0x77, 0x88, 0x00, 0xFF,
    ])
    if seed != expected:
        raise AssertionError("example seed bytes changed")
    challenge = b"test"
    nonce = bytes(range(32))
    body = build_body(1, challenge, nonce, seed, True)
    message, signature = body[:-SIG_SIZE], body[-SIG_SIZE:]
    if message != bytes([FLAG_CHECK_COUNTER, 0, 0, 0, 1, 4]) + challenge + nonce:
        raise AssertionError("signed layout")
    SigningKey(seed).verify_key.verify(message, signature)
    try:
        SigningKey(seed).verify_key.verify(message[:-1] + bytes([message[-1] ^ 1]), signature)
        raise AssertionError("tampered message was accepted")
    except Exception as exc:
        if type(exc).__name__ != "BadSignatureError":
            raise


def test_default_fragment() -> None:
    seed = parse_seed_hex(EXAMPLE_SEED_HEX)
    challenge = b"test"
    nonce = bytes([0x11]) * 32
    body = build_body(1, challenge, nonce, seed, True)
    frames, next_seq = fragment(body, 0, FLAG_CHECK_COUNTER, len(challenge))
    if len(body) != 106 or len(frames) != 6 or next_seq != 6:
        raise AssertionError((len(body), len(frames), next_seq))
    if frames[0][1] != AD_START or frames[-1][1] != AD_END:
        raise AssertionError("frame types")
    if any(frame[1] != AD_MIDDLE for frame in frames[1:-1]):
        raise AssertionError("middle type")
    for frame in frames:
        check_crc(frame)
        if len(frame) > 31:
            raise AssertionError("over 31")
    announce = frames[0]
    body_len = (announce[4] << 8) | announce[5]
    if body_len != 106 or announce[6] != 5 or announce[7] != PROTO_VERSION:
        raise AssertionError("announce meta")
    if announce[8] != FLAG_CHECK_COUNTER or announce[9] != 4:
        raise AssertionError("announce flags")
    if reassemble(frames) != body:
        raise AssertionError("reassembly")
    seqs = [((frame[2] << 8) | frame[3]) for frame in frames]
    if seqs != [0, 1, 2, 3, 4, 5]:
        raise AssertionError(seqs)


def test_sequence_carry_and_no_overlap() -> None:
    body = bytes(range(26 * 4 + 2))  # 106 bytes, 5 chunks, 6 frames
    frames, nxt = fragment(body, 250, 0, 0)
    seqs = [((frame[2] << 8) | frame[3]) for frame in frames]
    if seqs != [250, 251, 252, 253, 254, 255]:
        raise AssertionError(seqs)
    frames2, nxt2 = fragment(body, nxt, 0, 0)
    seqs2 = [((frame[2] << 8) | frame[3]) for frame in frames2]
    if seqs2 != [256, 257, 258, 259, 260, 261]:
        raise AssertionError(seqs2)
    if set(seqs) & set(seqs2):
        raise AssertionError("packets overlap")
    if nxt2 != 262:
        raise AssertionError(nxt2)


def test_counter_blocks() -> None:
    stored = None
    nxt = 1
    limit = 1
    used = []

    def reserve(start: int) -> None:
        nonlocal nxt, limit, stored
        if start > 0xFFFFFFFF - COUNTER_RESERVE:
            raise AssertionError("exhausted")
        limit = start + COUNTER_RESERVE
        stored = limit
        nxt = start

    def take() -> int:
        nonlocal nxt
        if nxt >= limit:
            reserve(limit)
        value = nxt
        nxt += 1
        return value

    reserve(1 if stored is None else stored)
    for _ in range(COUNTER_RESERVE):
        used.append(take())
    if used[0] != 1 or used[-1] != COUNTER_RESERVE or len(set(used)) != COUNTER_RESERVE:
        raise AssertionError("first block")
    # Reboot loads the saved high-water and must not repeat a used value.
    reboot_start = stored
    reserve(reboot_start)
    again = [take() for _ in range(3)]
    if again != [8193, 8194, 8195]:
        raise AssertionError(again)
    if set(again) & set(used):
        raise AssertionError("counter reused after reboot")
    if take_unchecked() != 0:
        raise AssertionError("test mode counter")


def take_unchecked() -> int:
    return 0


def test_unchecked_flag() -> None:
    seed = parse_seed_hex(EXAMPLE_SEED_HEX)
    body = build_body(0, b"test", b"\x22" * 32, seed, False)
    if body[0] != 0 or body[1:5] != b"\x00\x00\x00\x00":
        raise AssertionError("unchecked counter layout")


def test_max_challenge_fits() -> None:
    seed = parse_seed_hex(EXAMPLE_SEED_HEX)
    challenge = b"x" * 32
    body = build_body(2, challenge, b"\x33" * 32, seed, True)
    frames, _ = fragment(body, 0, FLAG_CHECK_COUNTER, 32)
    if len(body) != 134 or len(frames) != 7:
        raise AssertionError((len(body), len(frames)))
    for frame in frames:
        check_crc(frame)
    if reassemble(frames) != body:
        raise AssertionError("max challenge reassembly")


def main() -> None:
    test_crc_matches_firmware_shift()
    test_seed_and_signature()
    test_default_fragment()
    test_sequence_carry_and_no_overlap()
    test_counter_blocks()
    test_unchecked_flag()
    test_max_challenge_fits()
    print("ok")
    print("default body 106 bytes, 6 frames, seq 0-5")
    print("seq 250-255 carries into 256 on the next packet")
    print("counter 1..8192 then reboot continues at 8193")
    print("signature covers flags, counter, challenge, nonce")


if __name__ == "__main__":
    main()
