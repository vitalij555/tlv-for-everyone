import pytest
import sys


# insert at 1, 0 is the script path (or '' in REPL)
if not '../bit-parser' in sys.path:
    sys.path.insert(1, '../bit-parser')


from TlvParser.TlvParser import BerTlvElement, BerTlvParser, BerTlv


class TestBitParser:

    def test_tlv_find(self):
        ber_tlv_parser = BerTlvParser()
        tag_parsed = ber_tlv_parser.parse_tlv(
            b"6F398408A000000025010403A52D5010414D45524943414E20455850524553538701019F38069F35019F6E045F2D02656EBF0C079F0A0400010102")
        # pprint(f"\nAll tag as hex str: {tag_parsed.get_as_dict()}")
        print(f"\nAll tag as hex str: {tag_parsed.get_as_hex_str()}")
        print(f"\nTag found: {tag_parsed.find('6f/a5/bf0c')} {type(tag_parsed.find('6f/a5/bf0c'))}")
        print(f"\nTag found: {tag_parsed.find('6f/a5/87')} {type(tag_parsed.find('6f/a5/87'))}")
        print(f"As dict: {tag_parsed.get_as_dict()}")
        print(f"As list: {tag_parsed.get_as_list()}")


    def test_tlv_insert_ok(self):
        ber_tlv_parser = BerTlvParser()
        tag_parsed = ber_tlv_parser.parse_tlv(
            b"6F398408A000000025010403A52D5010414D45524943414E20455850524553538701019F38069F35019F6E045F2D02656EBF0C079F0A0400010102")
        print(f"\nAll tag as hex str: {tag_parsed.get_as_hex_str()}")
        tlv_element = BerTlvElement(b"\xF0")
        tag_parsed.insert_tlv_element("6f/84", tlv_element)
        print(f"\nAll tag as hex str: {tag_parsed.get_as_hex_str()}")


    def test_tlv_length_from_int(self):
        tlv_element = BerTlvElement(0xA0)

        assert tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(15) == bytes([0x0F])
        assert tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(127) == bytes([0x7F])

        # long-form
        assert tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(128) == bytes([0x81, 0x80])
        assert tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(255) == bytes([0x81, 0xFF])
        assert tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(256) == bytes([0x82, 0x01, 0x00])


    def test_encode(self):
        # DFD002  16  414d45524943414e2045585052455353
        # 5f2a  2  0124
        # 9a    3  220922
        tlv_element = BerTlvElement(0xA0)
        tlv_bytes_expected = bytes([0xA0, 0x00])
        tlv_bytes = tlv_element.encode()
        assert(tlv_bytes_expected == tlv_bytes)


        tlv_element = BerTlvElement(0xDFD002)
        tlv_bytes_expected = bytes([0xDF, 0xD0, 0x02, 0x00])
        tlv_bytes = tlv_element.encode()
        assert(tlv_bytes_expected == tlv_bytes)


        tlv_element = BerTlvElement(0xDFD002, bytes.fromhex("414d45524943414e2045585052455353"))
        tlv_bytes_expected = bytes([0xDF, 0xD0, 0x02, 16, 0x41, 0x4d, 0x45, 0x52, 0x49, 0x43, 0x41, 0x4e, 0x20, 0x45, 0x58, 0x50, 0x52, 0x45, 0x53, 0x53])
        tlv_bytes = tlv_element.encode()
        assert(tlv_bytes_expected == tlv_bytes)


        tlv_element = BerTlvElement(0x9F1E, bytes.fromhex("3032333435363738"))
        tlv_bytes_expected = bytes([0x9F, 0x1E, 0x08, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38])
        tlv_bytes = tlv_element.encode()
        assert(tlv_bytes_expected == tlv_bytes)


    def test_multi_root_siblings(self):
        p = BerTlvParser()
        tlv = p.parse_tlv("8401AA5A01BB")  # 84 len=1 AA, 5A len=1 BB
        d = tlv.get_as_dict()
        # Expect dummy FF root with two children
        assert "FF" in d
        root = d["FF"]
        assert "84" in root and "5A" in root


    def test_constructed_with_children(self):
        # A0 0A  9A03 250826  5F2A02 0124
        hex_str = "A00A9A032508265F2A020124"
        p = BerTlvParser()
        tlv = p.parse_tlv(hex_str)
        d = tlv.get_as_dict()
        assert "A0" in d
        inner = d["A0"]
        assert "9A" in inner and "5F2A" in inner


    def test_long_form_length_value_128(self):
        val = "00" * 128
        hex_str = "9F1E8180" + val  # 9F1E len=0x81 0x80, 128 zero bytes
        p = BerTlvParser()
        tlv = p.parse_tlv(hex_str)
        d = tlv.get_as_dict()
        assert "9F1E" in d
        # ensure the parser stored the whole value
        elem = tlv.tlv_elements["9f1e"] if "9f1e" in tlv.tlv_elements else tlv.tlv_elements["9F1E"]
        assert len(elem.get_value()) == 128


    def test_constructed_parent_long_length(self):
        # F0 uses long-form length (0x81 0x08) even though 8 fits in short-form
        # F0 81 08  9C 01 00  5F28 02 01 24
        hex_str = "F081089C01005F28020124"
        p = BerTlvParser()
        tlv = p.parse_tlv(hex_str)
        d = tlv.get_as_dict()
        assert "F0" in d
        assert "9C" in d["F0"] and "5F28" in d["F0"]


    def test_three_byte_tag(self):
        # DFD002 len=04 value=DEADBEEF
        hex_str = "DFD00204DEADBEEF"
        p = BerTlvParser()
        tlv = p.parse_tlv(hex_str)
        d = tlv.get_as_dict()
        assert "DFD002" in d


    def test_duplicate_children_raise(self):
        # A0 08  5F2A02 0124  5F2A02 0840  -> duplicate 5F2A
        hex_str = "A0085F2A0201245F2A020840"
        p = BerTlvParser()
        with pytest.raises(LookupError):
            p.parse_tlv(hex_str)


    def test_find_with_dummy_root(self):
        p = BerTlvParser()
        tlv = p.parse_tlv("8401AA5A01BB")
        # watch the traversal
        _ = tlv.find("ff/84", _debug=True)
        assert tlv.find("ff/84").get_value_as_hex_str().upper() == "AA"
        assert tlv.find("ff/5A").get_value_as_hex_str().upper() == "BB"


    def test_find_single_root_no_dummy(self):
        p = BerTlvParser()
        tlv = p.parse_tlv("A00A9A032508265F2A020124")
        assert tlv.find("A0/9A").get_value_as_hex_str().upper() == "250826"
        assert tlv.find("A0/5F2A").get_value_as_hex_str().upper() == "0124"


    def test_roundtrip_encode_decode(self):
        # Build: A0 { 9A=250826, 5F2A=0124 }
        parent = BerTlvElement(0xA0, {})
        child1 = BerTlvElement(0x9A, bytes.fromhex("250826"))
        child2 = BerTlvElement(0x5F2A, bytes.fromhex("0124"))
        parent.add_child(child1)
        parent.add_child(child2)
        enc = parent.encode().hex().upper()

        p = BerTlvParser()
        parsed = p.parse_tlv(enc)
        d = parsed.get_as_dict()
        assert "A0" in d and "9A" in d["A0"] and "5F2A" in d["A0"]
        # Values preserved
        assert parsed.find("A0/9A", _debug=True).get_value_as_hex_str().upper() == "250826"
        assert parsed.find("A0/5F2A", _debug=True).get_value_as_hex_str().upper() == "0124"


    def test_length_encoder_large_values(self):
        e = BerTlvElement(0xA0)
        assert e._BerTlvElement__convert_int_length_to_tlv_bytes(255)  == bytes([0x81, 0xFF])
        assert e._BerTlvElement__convert_int_length_to_tlv_bytes(256)  == bytes([0x82, 0x01, 0x00])
        assert e._BerTlvElement__convert_int_length_to_tlv_bytes(1000) == bytes([0x82, 0x03, 0xE8])


    def test_zero_length_value(self):
        p = BerTlvParser()
        tlv = p.parse_tlv("5F2A00")
        elem = tlv.tlv_elements["5f2a"] if "5f2a" in tlv.tlv_elements else tlv.tlv_elements["5F2A"]
        assert elem.get_length() == 0 and elem.get_value_as_hex_str() == ""


    def test_truncated_value_current_behavior(self):
        # Declared length 08 but only 2 bytes follow; current parser slices quietly.
        p = BerTlvParser()
        tlv = p.parse_tlv("9F1E083030")  # only 2 bytes of value
        elem = tlv.tlv_elements["9f1e"] if "9f1e" in tlv.tlv_elements else tlv.tlv_elements["9F1E"]
        # Document current behavior (value shorter than declared):
        assert len(elem.get_value()) == 2
        assert elem.get_length() == 8


    def test_hex_with_spaces_and_newlines(self):
        p = BerTlvParser()
        s = "84 01 AA \n 5A 01 BB"
        s = ''.join(ch for ch in s if ch in "0123456789abcdefABCDEF")
        tlv = p.parse_tlv(s)
        d = tlv.get_as_dict()
        assert "FF" in d and "84" in d["FF"] and "5A" in d["FF"]


from hypothesis import given, strategies as st

@given(tag=st.integers(min_value=0x01, max_value=0x1E),  # simple 1-byte tags (avoid constructed/high-tag-number here)
       data=st.binary(min_size=0, max_size=64))
def test_roundtrip_fuzz(tag, data):
    # force primitive tag in UNIVERSAL class (top 2 bits 00, constructed bit 0)
    first = (0b00 << 6) | (0 << 5) | (tag & 0x1F)
    elem = BerTlvElement(bytes([first]))
    elem.set_length(len(data))
    elem.set_value_bytes(data)
    enc = elem.encode().hex()
    parsed = BerTlvParser().parse_tlv(enc)
    # single root, compare
    e = parsed if isinstance(parsed, BerTlvElement) else next(iter(parsed.tlv_elements.values()))
    assert e.get_value() == data
