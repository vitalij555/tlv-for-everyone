import binascii
from enum import Enum, auto
from bitops import get_bit_range_as_int
from collections import namedtuple, OrderedDict
import pprint

from bitops.BinaryOperations import get_effective_length_in_bytes, set_bit_range_from_int, set_bit

DUMMY_TAG = 0xFF
PATH_SEPARATOR = "/"


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
    def __init__(self, tag, value = None):
        self.__tag_bytes = None
        if isinstance(tag, int):
            self.tag  = tag
            self.__tag_bytes = tag.to_bytes(get_effective_length_in_bytes(tag), byteorder = "big")
        elif isinstance(tag, bytes):
            self.tag  = int.from_bytes(tag, byteorder="big")
            self.__tag_bytes = tag

        self.is_dummy                = False
        if self.tag == DUMMY_TAG:
            self.is_dummy = True

        self.tag_class, self.is_constructed, self.__tag_type_first_octet, self.is_tag_long_form = self.__parse_tag(self.__tag_bytes[0])
        self.__value_bytes           = []

        self.__length_of_length     = 0
        self.__length_bytes         = [0]

        self.__children_tlvs = OrderedDict()

        if value:
            if isinstance(value, dict):
                for tag, tlv_item in value.items():
                    self.__children_tlvs[tag] = tlv_item
                    self.is_constructed = True
                    # TODO: check if it is necessary to do something with length here..
            else:
                for value_byte in value:
                    self.__value_bytes.append(value_byte)
                if len(self.__value_bytes):
                    self.__length_bytes     = self.__convert_int_length_to_tlv_bytes(len(self.__value_bytes))
                    self.__length_of_length = len(self.__length_bytes)

        # if length:
        #     self.__length_bytes     = self.__convert_int_length_to_tlv_bytes(length)
        #     self.__length_of_length = len(self.__length_bytes)

        self.is_length_long_form = False
        if len(self.__length_bytes) > 1:
            self.is_length_long_form = True


    def __str__(self):
        if len(self.__children_tlvs) > 0:
            return f"{self.get_tag().hex()}  {self.get_length()}"
        else:
            return f"{self.get_tag().hex()}  {self.get_length()}   {self.get_value_as_hex_str()}"

    def __repr__(self):
        if len(self.__children_tlvs) > 0:
            return f"{self.get_tag().hex()}  {self.get_length()}  {self.get_children()}"
        else:
            return f"{self.get_tag().hex()}  {self.get_length()}   {self.get_value_as_hex_str()}"

    def __parse_tag(self, first_byte):
        # byte = binascii.unhexlify(byteHexStr)
        tag_class = get_bit_range_as_int(first_byte, 6, 8)
        is_constructed = get_bit_range_as_int(first_byte, 5, 6)
        tag_type = get_bit_range_as_int(first_byte, 0, 5)
        return Tag(TLV_TAG_CLASS(tag_class), is_constructed, tag_type, tag_type == 31)

    def get_class(self):
        return self.tag_class

    def is_tag_type_constructed(self):
        return self.is_constructed

    def get_children(self):
        return self.__children_tlvs

    def get_tag(self):
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
        if isinstance(byte, int):
            byte = byte.to_bytes(1, byteorder="big")
        self.__tag_bytes += byte

    def set_length_of_length(self, length_of_length):
        self.__length_of_length = length_of_length

    def clear_length_bytes(self):
        self.__length_bytes.clear()

    def set_length(self, length):
        self.clear_length_bytes()
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
        # print(f"Bytes are: {self.__value_bytes}")
        return (bytes(self.__value_bytes)).hex()

    def get_value_as_int(self):
        pass

    def add_child(self, tlv):
        if isinstance(tlv, str):
            raise AssertionError(f"Str input is not supported by add_child function. Passed value: {tlv}")
        if isinstance(tlv, list):
            pass # TODO: Implement this
            # self.__children_tlvs.extend(tlv)
        elif isinstance(tlv, (dict, OrderedDict)):
            self.__children_tlvs.updte(tlv)
        else:
            if (tag_name:=tlv.get_tag().hex().upper()) in self.__children_tlvs:
                raise LookupError(f"Tag duplication while parsing: {tag_name}")
            self.__children_tlvs[tag_name] = tlv
            # print(f"Children dict after update: {self.__children_tlvs}")

    def get_as_list(self, tlv_element=None):
        if not tlv_element:
            tlv_element = self
        unfolded = [self.get_as_list(child) for child in tlv_element.__children_tlvs.values()]
        # print(f"Processed: { [tlv_element, unfolded]}")
        if len(unfolded) > 0:
            return [tlv_element, unfolded]
        else:
            return tlv_element

    def get_as_dict(self, tlv_element = None):
        if not tlv_element:
            tlv_element = self
            # print(f"Returning dict with: {tlv_element.get_tag().hex().upper()}")
            return {tlv_element.get_tag().hex().upper(): self.get_as_dict(tlv_element)}
        # print(f"Next tlv tag is {tlv_element}")
        unfolded = {tag_name: self.get_as_dict(child) for tag_name, child in tlv_element.__children_tlvs.items()}
        # print(f"Returning: {unfolded or tlv_element}")
        return unfolded or tlv_element

    def get_as_hex_str(self):
        l = self.get_as_dict()
        return pprint.pformat(l, indent=4)

    def __convert_int_length_to_tlv_bytes(self, length):
        result = bytes()
        first_byte = 0x00

        if length > 127:
            length_bytes = length.to_bytes()
            first_byte = set_bit(first_byte, 7)
            first_byte = set_bit_range_from_int(first_byte, 0, len(length_bytes))

            result += first_byte.to_bytes()
            for byte in length_bytes[1:]:
                result += byte

            return result
        else:
            return bytes([length])

    def __encode_child_elemens(self):
        result = bytes()
        for tag_str, tlv_element in self.__children_tlvs:
            result += tlv_element.encode()
        return result

    def encode(self):
        result = bytes()
        first_byte = 0b00
        first_byte = set_bit_range_from_int(first_byte, 6, self.tag_class.value)
        if len(self.__children_tlvs) > 0:
            self.is_constructed = True
        if self.is_constructed:
            first_byte = set_bit_range_from_int(first_byte, 5, 1)
        first_byte = set_bit_range_from_int(first_byte, 0, self.__tag_type_first_octet)
        if self.is_tag_long_form:
            first_byte = set_bit_range_from_int(first_byte, 0, 31)
        result += first_byte.to_bytes()
        result += bytes(self.__tag_bytes[1:])
        result += bytes(self.__length_bytes)
        if not self.is_constructed:
            result += bytes(self.__value_bytes)
        else:
            result += self.__encode_child_elemens()

        return result

    def get_as_xml_str(self):
        #TODO: Implement this
        pass


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
        # print(f"{current_state}  ==>  {next_state}")
        return next_state

    # def __init__(self):
        # self.__current_parsing_state = BerTlvParser.state.EXPECTING_TAG

    def parse_tlv(self, bytesHexStr, parent_tlv = None):
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
                if tlv_tag.is_tag_long_form:
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
                    tlv_tag.clear_length_bytes()   # we need this line  because by default empty tag already has one zero byte assigned as a length byte
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
                        self.parse_tlv(tlv_tag.get_value_as_hex_str(), tlv_tag)
                    if parent_tlv:
                        parent_tlv.add_child(tlv_tag)
                        # tlv_tag = None
                    else:
                        return BerTlv(tlv_tag)
        return BerTlv(tlv_tag)

    def __parse_tag_next_byte(self, byte):
        more     = (1 == get_bit_range_as_int(byte, 7, 8))
        tag_type = get_bit_range_as_int(byte, 0, 8)
        # print(f"more: {more}")
        # print(f"tag_type: {tag_type:02X}")
        return TagTypeBytes(more, tag_type)

    def __parse_length(self, byte):
        is_long_form = (1 == get_bit_range_as_int(byte, 7, 8))
        length       = get_bit_range_as_int(byte, 0, 7)
        # print(f"is_long_form: {is_long_form}")
        # print(f"length: {length}")
        return Length(is_long_form, length)



class BerTlv():
    def __init__(self, data):
        self.tlv_elements = OrderedDict()
        if isinstance(data, (str, bytes)):
            parser = BerTlvParser()
            parsed_elements = parser.parse_tlv(data)
            for parsed_element in parsed_elements:
                self.tlv_elements[parsed_element.get_tag().hex()] = parsed_element
        elif isinstance(data, BerTlvElement):
            self.tlv_elements[data.get_tag().hex()] = data
        elif isinstance(data, list):
            for tlv_element in data:
                self.tlv_elements[tlv_element.get_tag().hex()] = tlv_element
        elif isinstance(data, dict):
            for tag, tlv_element in data.items():
                self.tlv_elements[tag] = tlv_element

    # def get_tlv_tree_from_list(self, l_tlv, destination_dict):
    #     if len(destination_dict == 0):
    #         for tlv_element in l_tlv:
    #             if len(tlv_element.get_children()) > 0:
    #                 self.get_tlv_tree_from_list(l_tlv, destination_dict)
    #

    def __wrap_with_dummy_tag(self):
        if len(self.tlv_elements) == 0:
            return None
        if len(self.tlv_elements) > 1:  # if we have a list of elements here, then, first wrap it with a dummy tag first
            dummy_tag = BerTlvElement(DUMMY_TAG)
            dummy_tag.add_child(self.tlv_elements)
            return dummy_tag
        else:
            first_key = next(iter(self.tlv_elements))
            return self.tlv_elements[first_key]

    def find(self, path):
        if not path:
            #TODO: log warning here
            return None
        path = path.upper()
        path_elements = path.split("/")
        root_tag = None
        if len(self.tlv_elements) > 1:  # if we have a list of elements here, then, first wrap it with a dummy tag
            path_elements.insert(0, "FF")
        root_tag = self.__wrap_with_dummy_tag()
        if not root_tag:
            return None

        # tag_dict = root_tag.get_as_dict()
        current_tag = root_tag
        for path_element in path_elements:
            if isinstance(current_tag, BerTlvElement):
                if current_tag.get_tag().hex().upper() == path_element:
                    current_tag = current_tag.get_children()
                else:
                    return None
            elif isinstance(current_tag, OrderedDict):
                current_tag = current_tag.get(path_element, None)
            if not current_tag:
                return None
        return current_tag


    def insert_tlv_element(self, path, tlv_element):
        find_rez = self.find(path)      #[0:path.rfind(PATH_SEPARATOR)])
        if find_rez:
            if isinstance(find_rez, BerTlvElement):
                find_rez.add_child(tlv_element)
            else:
                print(f"find_rez before insert: {find_rez}")
                find_rez[tlv_element.get_tag().hex()] = tlv_element
                print(f"find_rez after insert: {find_rez}")
        else:
            raise LookupError(f"Unable to find path: {path}")


    def insert_tlv_as_hex_str(self, path, hex_str):
        pass


    def update_tlv_element(self, tlv_element, dict):
        pass


    # def insert_tlv_as_hex_str_after(self, path, hex_str):
    #     tag = self.find(path)
    #     if not tag:
    #         raise AssertionError(f"Tag {path} not found")
    #
    #     parser = BerTlvParser()
    #     tlv_element = parser.parse_tlv(hex_str)
    #     if not tlv_element:
    #         raise AssertionError(f"Unable to parse hex string as TLV sequence ({path}): {hex_str}")
    #
    #     if isinstance(tag, dict):
    #         self.
    #     elif isinstance(tag, BerTlvElement):
    #         self.


    def insert_tag(self, path, tag, value):
        pass


    def create_tlv_element(self, tag_class, tag_type):
        pass
        # tlv_element =


    def encode(self):
        result = bytes()
        for tlv_element in self.tlv_elements:
            result+=tlv_element.decode()

    def get_as_list(self, tlv_element = None):
        root_tag = self.__wrap_with_dummy_tag()
        if not root_tag:
            return ""
        return root_tag.get_as_list()


    def get_as_dict(self, tlv_element = None):
        root_tag = self.__wrap_with_dummy_tag()
        if not root_tag:
            return ""
        return root_tag.get_as_dict()


    def get_as_hex_str(self):
        root_tag = self.__wrap_with_dummy_tag()
        if not root_tag:
            return ""
        return root_tag.get_as_hex_str()


    def get_as_xml_str(self):
        #TODO: Implement this
        pass


    def get_as_json(self):
        #TODO: Implement this
        pass


