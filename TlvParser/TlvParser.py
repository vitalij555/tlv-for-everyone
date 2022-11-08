import binascii
from enum import Enum, auto
from bitops import get_bit_range_as_int
from collections import namedtuple


class TLV_TAG_CLASS(Enum):
    UNIVERSAL        = 0
    APPLICATION      = auto()
    CONTEXT_SPECIFIC = auto()
    PRIVATE          = auto()


class TLV_LENGTH_TYPE(Enum):
    DEFINITE_SHORT = 0
    INDEFINITE     = auto()
    DEFINITE_LONG  = auto()
    RESERVED       = auto()


class TLV_TAG_TYPE(Enum):
    END_OF_CONTENT    = 0,
    BOOLEAN           = ()
    INTEGER           = ()
    BIT_STRING        = ()
    OCTET_STRING      = ()
    NULL              = ()
    OBJECT_IDENTIFIER = ()
    OBJECT_DESCRIPTOR = ()
    EXTERNAL          = ()
    REAL              = ()
    ENUMERATED        = ()
    EMBEDDED_PDV      = ()
    UTF8STRING        = ()
    RELATIVE_OID      = ()
    TIME              = ()
    RESERVED          = ()
    SEQUENCE          = ()
    SET               = ()
    NUMERICSTRING     = ()
    PRINTABLESTRING   = ()
    T61STRING         = ()
    VIDEOTEXSTRING    = ()
    IA5STRING         = ()
    UTCTIME           = ()
    GENERALIZED_TIME  = ()
    GRAPHIC_STRING    = ()
    VISIBLE_STRING    = ()
    GENERAL_STRING    = ()
    UNIVERSAL_STRING  = ()
    CHARACTER_STRING  = ()
    BMP_STRING        = ()
    DATE              = ()
    TIME_OF_DAY       = ()
    DATE_TIME         = ()
    DURATION          = ()
    OID_IRI           = ()
    RELATIVE_OID_IRI  = ()


class BerTlvElement():
    def __init__(self, tag):
        self.tag                     = int(tag)
        self.tag_class, self.is_constructed, self.__tag_type_first_octet, self.is_long_form = self.__parse_tag(tag)
        self.__value_bytes           = []
        self.__length_bytes          = []
        self.__length_of_length      = 0
        self.is_length_long_form     = False
        self.__tag_bytes             = []
        self.__tag_bytes.append(tag)
        self.__children_tlvs         = []
        # self.length = 0
        self.__is_complete           = False
        self.__is_valid              = False


    def __str__(self):
        if len(self.__children_tlvs) > 0:
            return f"""{self.get_tag().hex()}  {self.get_length()} 
    {self.__children_tlvs}"""
        else:
            return f"{self.get_tag().hex()}  {self.get_length()}   {self.get_value_as_hex_str()}"


    def __repr__(self):
        if len(self.__children_tlvs) > 0:
            return f"""{self.get_tag().hex()}  {self.get_length()}  
    {self.__children_tlvs}
        """
        else:
            return f"""{self.get_tag().hex()}  {self.get_length()}   {self.get_value_as_hex_str()}"""


    def __parse_tag(self, byte):
        tag_class = get_bit_range_as_int(byte, 6, 8)
        is_constructed = get_bit_range_as_int(byte, 5, 6)
        tag_type = get_bit_range_as_int(byte, 0, 5)
        # print(f"tag analysed: {byte:02X}")
        # print(f"tag_class: {tag_class:02X}")
        # print(f"is_constructed: {is_constructed}")
        # print(f"tag_type: {tag_type}")
        return Tag(TLV_TAG_CLASS(tag_class), is_constructed, tag_type, tag_type == 31)

    def get_class(self):
        pass

    def is_tag_type_constructed(self):
        return self.is_constructed

    def get_tag(self):
        # if not self.__is_complete:
        #     raise AssertionError("Tag is not complete!")
        return bytes(self.__tag_bytes)

    def get_value(self):
        if not self.__is_complete:
            return None

        return bytes(self.__value_bytes)

    def is_tag_long_form(self):
        return self.__is_tag_type_long_form

    def is_tag_constructed(self):
        return self.is_tag_constructed()

    def set_tag_type_bytes(self, bytes):
        self.__tag_bytes = bytes

    def add_tag_type_byte(self, byte):
        self.__tag_bytes.append(byte)

    def set_length_of_length(self, length_of_length):
        self.__length_of_length = length_of_length

    def set_length(self, length):
        self.__length_bytes.clear()
        self.__length_bytes.append(length.to_bytes(1, 'big')[0])

    def get_length(self):
        return int.from_bytes(self.__length_bytes, "big")

    def set_length_bytes(self, bytes):
        self.__length_bytes = bytes

    def add_length_byte(self, byte):
        'returns number of bytes left'
        self.__length_bytes.append(byte)
        # print(f"Length bytes left: {self.__length_of_length - len(self.__length_bytes)}")
        return self.__length_of_length - len(self.__length_bytes)

    def set_value_bytes(self, bytes):
        self.__value_bytes = bytes

    def set_value(self, value_byte):
        self.__value_bytes.clear()
        self.__value_bytes.append(value_byte.to_bytes(1, 'big')[0])
        # print(f"Now value is: { [binascii.hexlify(byte.to_bytes(1, 'big')) for byte in self.__value_bytes]}")
        # print(f"Length bytes left: {self.get_length() - len(self.__value_bytes)}")
        return self.get_length() - len(self.__value_bytes)

    def add_value_byte(self, byte):
        'returns number of bytes left'
        self.__value_bytes.append(byte)
        # print(f"Length bytes left: {self.get_length() - len(self.__value_bytes)}")
        # print(f"Now value is: { [binascii.hexlify(byte.to_bytes(1, 'big')) for byte in self.__value_bytes]}")
        return self.get_length() - len(self.__value_bytes)

    def get_value_as_hex_str(self):
        return (bytes(self.__value_bytes)).hex()

    def get_value_as_int(self):
        pass

    def mark_as_complete(self):
        self.__is_complete = True

    def add_child(self, tlv):
        self.__children_tlvs.append(tlv)


Tag = namedtuple('Tag', ['tag_class', 'is_constructed', 'tag_type', 'is_long_form'])
TagTypeBytes = namedtuple('TagTypeBytes', ['more', 'tag_type'])
Length = namedtuple('Length', ['is_long_form', 'length'])


class BerTlvParser():
    class state(Enum):
        EXPECTING_TAG              = 0,
        EXPECTING_TAG_NEXT_BYTE    = auto(),
        EXPECTING_LENGTH           = auto(),
        EXPECTING_LENGTH_NEXT_BYTE = auto(),
        EXPECTING_VALUE            = auto(),
        EXPECTING_VALUE_NEXT_BYTE  = auto(),

    def changeParsingState(self, current_state, next_state):
        # self.__current_parsing_state = next_state
        print(f"{current_state}  ==>  {next_state}")
        return next_state

    # def __init__(self):
        # self.__current_parsing_state = BerTlvParser.state.EXPECTING_TAG

    def parse_tlv_hex_str(self, bytesHexStr, parent_tlv = None):
        print(f"parse_tlv_hex_str called for {bytesHexStr}")
        bytes = binascii.unhexlify(bytesHexStr)
        tlv_tag = None
        current_parsing_state = BerTlvParser.state.EXPECTING_TAG
        # currentTag
        raw_bytes_length = len(bytes)
        for idx, byte in enumerate(bytes):
            # print(f"Current byte is: {byte:02X}")
            if current_parsing_state == BerTlvParser.state.EXPECTING_TAG:
                tlv_tag = BerTlvElement(byte)
                if tlv_tag.is_long_form:
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_TAG_NEXT_BYTE)
                else:
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_LENGTH)

            elif current_parsing_state == BerTlvParser.state.EXPECTING_TAG_NEXT_BYTE:
                tag_type_data = self.__parse_tag_next_byte(byte)
                tlv_tag.add_tag_type_byte(tag_type_data.tag_type)
                if not tag_type_data.more:
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_LENGTH)

            elif current_parsing_state == BerTlvParser.state.EXPECTING_LENGTH:
                length = self.__parse_length(byte)
                if length.is_long_form:
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_LENGTH_NEXT_BYTE)
                    tlv_tag.set_length_of_length(length.length)
                else:
                    tlv_tag.set_length(length.length)
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_VALUE)

            elif current_parsing_state == BerTlvParser.state.EXPECTING_LENGTH_NEXT_BYTE:
                if 0 == tlv_tag.add_length_byte(byte):
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_VALUE)

            elif current_parsing_state == BerTlvParser.state.EXPECTING_VALUE:
                if 0 != tlv_tag.set_value(byte):
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_VALUE_NEXT_BYTE)
                else:
                    if parent_tlv:
                        parent_tlv.add_child(tlv_tag)
                        current_parsing_state = self.changeParsingState(current_parsing_state,
                                                                        BerTlvParser.state.EXPECTING_TAG)

                    else:
                        return tlv_tag


            elif current_parsing_state == BerTlvParser.state.EXPECTING_VALUE_NEXT_BYTE:
                if 0 == tlv_tag.add_value_byte(byte):
                    current_parsing_state = self.changeParsingState(current_parsing_state, BerTlvParser.state.EXPECTING_TAG)
                    if tlv_tag.is_constructed:
                        self.parse_tlv_hex_str(tlv_tag.get_value_as_hex_str(), tlv_tag)
                    if parent_tlv:
                        parent_tlv.add_child(tlv_tag)
                        # tlv_tag = None
                    else:
                        return tlv_tag

                    # if idx+1 < raw_bytes_length and parent_tlv:
                    #     parent_tlv.add_child(tlv_tag)
                    #     tlv_tag = None
                    # elif idx+1 < raw_bytes_length:
                    #     print("TODO: log warning here: not all bytes used in parsing")


        # else:
        #     if tlv_tag.is_constructed:
        #         child_tlv = self.parse_tlv_hex_str(tlv_tag.get_value_as_hex_str(), tlv_tag)
        #         tlv_tag.add_child(child_tlv)
        #     tlv_tag.mark_as_complete()
        return tlv_tag

    def __parse_tag_next_byte(self, byte):
        more     = (1 == get_bit_range_as_int(byte, 7, 8))
        tag_type = get_bit_range_as_int(byte, 0, 8)
        print(f"more: {more}")
        print(f"tag_type: {tag_type:02X}")
        return TagTypeBytes(more, tag_type)

    def __parse_length(self, byte):
        is_long_form = (1 == get_bit_range_as_int(byte, 7, 8))
        length       = get_bit_range_as_int(byte, 0, 7)
        print(f"is_long_form: {is_long_form}")
        print(f"length: {length}")
        return Length(is_long_form, length)






