import binascii
import pytest
from unittest.mock import Mock
import sys
from pprint import pprint

# insert at 1, 0 is the script path (or '' in REPL)
if not '../bit-parser' in sys.path:
    sys.path.insert(1, '../bit-parser')


from TlvParser.TlvParser import BerTlvElement, BerTlvParser, BerTlv


class TestBitParser:
    # def test_simple_tlv_parse(self):
    #     ber_tlv_parser = BerTlvParser()
    #     #     # tag_parsed = ber_tlv_parser.parse_tlv(b"6F1A8407A0000000041010A50F500A4D617374657243617264870101")
    #     #     # print(tag_parsed)
    #     #     tag_parsed = ber_tlv_parser.parse_tlv(b"6F398408A000000025010403A52D5010414D45524943414E20455850524553538701019F38069F35019F6E045F2D02656EBF0C079F0A0400010102")
    #     #     # print(tag_parsed.get_as_hex_str())
    #     #     print(tag_parsed.get_as_dict())
    #
    #     tag_parsed = ber_tlv_parser.parse_tlv("F081FADF4204000000009F3901009F4104000000009F370412A450CD950500000000009A032209229F21031426389C01005F2A0201249F1A0208409F34033F00009F3303E0E8889F3501229F1E0830323334353637388408A0000000250104039F090200019B0200009F0606A000000025019F02060000000015019F03060000000000009F1210414D45524943414E2045585052455353DFD00210414D45524943414E2045585052455353DF21050000000000DF2205C400000000DF2305DC508400009F4005F000B0A0015F2D02656E5F360102C20400000010DF64200000002620000000FFFFFFFF00000000000004000000003C0300000000000C48")
    #     print(tag_parsed.get_as_hex_str())
        # print(tag_parsed.get_as_dict())

        # tag_parsed = ber_tlv_parser.parse_tlv_hex_str(b"F013DF6601004F06A00000002501DFAB010300000000")
        # print(tag_parsed)


    # def test_tlv_create(self):
    #     tlv = BerTlv(0x6F)


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
        expected = bytes([15])
        actual = tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(15)
        assert (expected == actual)

        expected = bytes([127])
        actual = tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(127)
        assert (expected == actual)

        expected = bytes([0b10000001])
        actual = tlv_element._BerTlvElement__convert_int_length_to_tlv_bytes(128)
        assert(expected == actual)


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
