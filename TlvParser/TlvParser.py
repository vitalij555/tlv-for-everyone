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


Tag = namedtuple('Tag', ['tag_class', 'is_constructed', 'tag_type', 'is_long_form'])
TagTypeBytes = namedtuple('TagTypeBytes', ['more', 'tag_type'])
Length = namedtuple('Length', ['is_long_form', 'length'])


class BerTlvElement():
    def __init__(self, tag, value=None):
        self.__tag_bytes = None
        if isinstance(tag, int):
            self.tag = tag
            self.__tag_bytes = tag.to_bytes(get_effective_length_in_bytes(tag), byteorder="big")
        elif isinstance(tag, bytes):
            self.tag = int.from_bytes(tag, byteorder="big")
            self.__tag_bytes = tag
        else:
            raise TypeError("tag must be int or bytes")

        self.is_dummy = (self.tag == DUMMY_TAG)

        parsed = self.__parse_tag(self.__tag_bytes[0])
        self.tag_class = parsed.tag_class
        self.is_constructed = bool(parsed.is_constructed)
        self.__tag_type_first_octet = parsed.tag_type
        self.__is_tag_long_form = bool(parsed.is_long_form)

        self.__value_bytes = bytearray()

        self.__length_of_length = 0
        self.__length_bytes = bytearray([0])

        self.__children_tlvs = OrderedDict()

        if value is not None:
            if isinstance(value, dict):
                for t, tlv_item in value.items():
                    self.__children_tlvs[t] = tlv_item
                self.is_constructed = True
            else:
                # value is bytes-like
                for b in value:
                    self.__value_bytes.append(b)
                if len(self.__value_bytes):
                    self.__length_bytes = bytearray(self.__convert_int_length_to_tlv_bytes(len(self.__value_bytes)))
                    self.__length_of_length = len(self.__length_bytes)

        self.is_length_long_form = (len(self.__length_bytes) > 1)

    def __eq__(self, other):
        return self.get_tag() == other.get_tag() and \
               self.get_length() == other.get_length() and \
               self.get_value() == other.get_value()

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
        return bytes(self.__value_bytes)

    def is_tag_long_form(self):
        return self.__is_tag_long_form

    def is_tag_constructed(self):
        return self.is_constructed

    def set_tag_type_bytes(self, b):
        self.__tag_bytes = b

    def add_tag_type_byte(self, byte):
        if isinstance(byte, int):
            byte = byte.to_bytes(1, byteorder="big")
        self.__tag_bytes += byte

    def set_length_of_length(self, length_of_length):
        self.__length_of_length = length_of_length

    def clear_length_bytes(self):
        self.__length_bytes = bytearray()

    def set_length(self, length):
        self.clear_length_bytes()
        self.__length_bytes.append(length & 0xFF)

    def get_length(self):
        return int.from_bytes(bytes(self.__length_bytes), "big") if self.__length_bytes else 0

    def set_length_bytes(self, b):
        # Accept bytes/bytearray/list of ints
        if isinstance(b, (bytes, bytearray)):
            self.__length_bytes = bytearray(b)
        else:
            self.__length_bytes = bytearray(b)

    def add_length_byte(self, byte):
        self.__length_bytes.append(byte & 0xFF)
        return self.__length_of_length - len(self.__length_bytes)

    def set_value_bytes(self, b):
        if isinstance(b, (bytes, bytearray)):
            self.__value_bytes = bytearray(b)
        else:
            # list of ints
            self.__value_bytes = bytearray(b)

    def set_value(self, value_byte):
        self.__value_bytes = bytearray()
        self.__value_bytes.append(value_byte & 0xFF)
        return self.get_length() - len(self.__value_bytes)

    def add_value_byte(self, byte):
        self.__value_bytes.append(byte & 0xFF)
        return self.get_length() - len(self.__value_bytes)

    def get_value_as_hex_str(self):
        return (bytes(self.__value_bytes)).hex()

    def get_value_as_int(self):
        # optional: implement when needed
        pass

    def add_child(self, tlv):
        if isinstance(tlv, str):
            raise AssertionError(f"Str input is not supported by add_child function. Passed value: {tlv}")
        if isinstance(tlv, list):
            # Optional: bulk insert
            for it in tlv:
                self.add_child(it)
        elif isinstance(tlv, (dict, OrderedDict)):
            for k, v in tlv.items():
                self.__children_tlvs[k.upper()] = v
        else:
            tag_name = tlv.get_tag().hex().upper()
            if tag_name in self.__children_tlvs:
                raise LookupError(f"Tag duplication while parsing: {tag_name}")
            self.__children_tlvs[tag_name] = tlv

    def get_as_list(self, tlv_element=None):
        if not tlv_element:
            tlv_element = self
        unfolded = [self.get_as_list(child) for child in tlv_element.__children_tlvs.values()]
        return [tlv_element, unfolded] if len(unfolded) > 0 else tlv_element

    def get_as_dict(self, tlv_element=None):
        if not tlv_element:
            tlv_element = self
            return {tlv_element.get_tag().hex().upper(): self.get_as_dict(tlv_element)}
        unfolded = {tag_name: self.get_as_dict(child) for tag_name, child in tlv_element.__children_tlvs.items()}
        return unfolded or tlv_element

    def get_as_hex_str(self):
        l = self.get_as_dict()
        return pprint.pformat(l, indent=4)

    def __convert_int_length_to_tlv_bytes(self, length: int) -> bytes:
        if length <= 127:
            return bytes([length])
        lb = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(lb)]) + lb

    def __encode_child_elemens(self):
        result = bytes()
        for _, tlv_element in self.__children_tlvs.items():  # iterate items
            result += tlv_element.encode()
        return result

    def encode(self):
        # build first tag octet
        first_byte = 0
        first_byte = set_bit_range_from_int(first_byte, 6, self.tag_class.value)
        is_constructed_now = (len(self.__children_tlvs) > 0) or self.is_constructed
        if is_constructed_now:
            first_byte = set_bit_range_from_int(first_byte, 5, 1)
        first_byte = set_bit_range_from_int(first_byte, 0, self.__tag_type_first_octet)
        if self.__is_tag_long_form:
            first_byte = set_bit_range_from_int(first_byte, 0, 31)

        tag_bytes = bytes([first_byte]) + bytes(self.__tag_bytes[1:])

        if is_constructed_now:
            # encode children and set length from their total size
            children_bytes = self.__encode_child_elemens()
            self.__length_bytes = bytearray(self.__convert_int_length_to_tlv_bytes(len(children_bytes)))
            return tag_bytes + bytes(self.__length_bytes) + children_bytes
        else:
            # primitive: set length from current value
            self.__length_bytes = bytearray(self.__convert_int_length_to_tlv_bytes(len(self.__value_bytes)))
            return tag_bytes + bytes(self.__length_bytes) + bytes(self.__value_bytes)

    def get_as_xml_str(self):
        # TODO: Implement this if needed
        pass


class BerTlvParser():
    class state(Enum):
        EXPECTING_TAG              = 0,
        EXPECTING_TAG_NEXT_BYTE    = auto(),
        EXPECTING_LENGTH           = auto(),
        EXPECTING_LENGTH_NEXT_BYTE = auto(),
        EXPECTING_VALUE            = auto(),
        EXPECTING_VALUE_NEXT_BYTE  = auto(),

    def changeParsingState(self, current_state, next_state):
        return next_state

    def parse_tlv(self, bytesHexStr, parent_tlv=None):
        b = binascii.unhexlify(bytesHexStr)
        i = 0
        result = [] if parent_tlv is None else None

        while i < len(b):
            # TAG (incl. long-form)
            first = b[i]; i += 1
            tlv_tag = BerTlvElement(first)
            if tlv_tag.is_tag_long_form():
                while True:
                    nxt = b[i]; i += 1
                    tnb = self.__parse_tag_next_byte(nxt)
                    tlv_tag.add_tag_type_byte(tnb.tag_type)
                    if not tnb.more:
                        break

            # LENGTH (short/long)
            first_len = b[i]; i += 1
            ln = self.__parse_length(first_len)
            if ln.is_long_form:
                tlv_tag.set_length_of_length(ln.length)
                tlv_tag.clear_length_bytes()
                for _ in range(ln.length):
                    tlv_tag.add_length_byte(b[i]); i += 1
            else:
                tlv_tag.set_length(ln.length)

            L = tlv_tag.get_length()

            # VALUE
            val = b[i:i + L]; i += L
            tlv_tag.set_value_bytes(val)

            # recurse if constructed
            if tlv_tag.is_constructed:
                self.parse_tlv(tlv_tag.get_value_as_hex_str(), tlv_tag)

            # attach to parent or top-level result  (this was missing in your failing run)
            if parent_tlv is not None:
                parent_tlv.add_child(tlv_tag)
            else:
                result.append(tlv_tag)

        # returns
        if parent_tlv is not None:
            return parent_tlv
        if not result:
            return None
        return BerTlv(result if len(result) > 1 else result[0])

    def __parse_tag_next_byte(self, byte):
        more = (1 == get_bit_range_as_int(byte, 7, 8))
        tag_type = get_bit_range_as_int(byte, 0, 8)
        return TagTypeBytes(more, tag_type)

    def __parse_length(self, byte):
        is_long_form = (1 == get_bit_range_as_int(byte, 7, 8))
        length = get_bit_range_as_int(byte, 0, 7)
        return Length(is_long_form, length)


class BerTlv():
    def __init__(self, data):
        self.tlv_elements = OrderedDict()
        if isinstance(data, (str, bytes)):
            parser = BerTlvParser()
            parsed = parser.parse_tlv(data)
            if isinstance(parsed, BerTlv):
                for k, v in parsed.tlv_elements.items():
                    self.tlv_elements[k.upper()] = v
            elif isinstance(parsed, BerTlvElement):
                self.tlv_elements[parsed.get_tag().hex().upper()] = parsed   # UPPER
            elif isinstance(parsed, list):
                for tlv_element in data:
                    self.tlv_elements[tlv_element.get_tag().hex().upper()] = tlv_element   # UPPER
        elif isinstance(data, BerTlvElement):
            self.tlv_elements[data.get_tag().hex().upper()] = data
        elif isinstance(data, list):
            for tlv_element in data:
                self.tlv_elements[tlv_element.get_tag().hex().upper()] = tlv_element
        elif isinstance(data, dict):
            for tag, tlv_element in data.items():
                self.tlv_elements[tag.upper()] = tlv_element


    def __wrap_with_dummy_tag(self):
        if len(self.tlv_elements) == 0:
            return None
        if len(self.tlv_elements) > 1:
            dummy_tag = BerTlvElement(DUMMY_TAG)
            dummy_tag.add_child(self.tlv_elements)
            return dummy_tag
        else:
            first_key = next(iter(self.tlv_elements))
            return self.tlv_elements[first_key]

    def find(self, path, _debug: bool = False):
        if not path:
            return None
        path = path.upper()
        path_elems = path.split("/")

        root_tag = self.__wrap_with_dummy_tag()
        if _debug:
            print(f"[find] path={path}  elems={path_elems}")
            print(f"[find] have {len(self.tlv_elements)} root TLVs; dummy used? "
                  f"{isinstance(root_tag, BerTlvElement) and root_tag.is_dummy}")

        if not root_tag:
            if _debug: print("[find] no root_tag")
            return None

        # If we wrapped in a dummy FF, allow both "FF/..." and just "..."
        if isinstance(root_tag, BerTlvElement) and getattr(root_tag, "is_dummy", False):
            if path_elems and path_elems[0] == "FF":
                if _debug: print("[find] stripping leading FF from path")
                path_elems = path_elems[1:]
            current = root_tag.get_children()  # start from children dict
        else:
            # Single-root case: do NOT inject FF
            current = root_tag

        # Walk the path
        for idx, seg in enumerate(path_elems):
            if isinstance(current, BerTlvElement):
                if _debug:
                    print(f"[find] at BerTlvElement tag={current.get_tag().hex().upper()} seg={seg}")
                if current.get_tag().hex().upper() == seg:
                    current = current.get_children()
                else:
                    if _debug: print("[find] tag mismatch")
                    return None
            elif isinstance(current, OrderedDict):
                if _debug:
                    print(f"[find] at OrderedDict; keys={list(current.keys())}  seg={seg}")
                # case-insensitive lookup
                upper_map = {k.upper(): v for k, v in current.items()}
                hit = upper_map.get(seg)
                if hit is None:
                    if _debug: print("[find] key not found in dict")
                    return None
                if idx < len(path_elems) - 1:
                    current = hit.get_children()
                else:
                    current = hit
            else:
                if _debug: print(f"[find] unexpected type: {type(current)}")
                return None

            if current is None:
                if _debug: print("[find] current is None after step")
                return None

        if _debug:
            if isinstance(current, BerTlvElement):
                print(f"[find] result: tag={current.get_tag().hex().upper()} "
                      f"len={current.get_length()} val={current.get_value_as_hex_str().upper()}")
            else:
                print(f"[find] result: dict keys={list(current.keys())}")
        return current


    def insert_tlv_element(self, path, tlv_element):
        find_rez = self.find(path)
        if find_rez:
            if isinstance(find_rez, BerTlvElement):
                find_rez.add_child(tlv_element)
            else:
                find_rez[tlv_element.get_tag().hex()] = tlv_element
        else:
            raise LookupError(f"Unable to find path: {path}")

    def insert_tlv_as_hex_str(self, path, hex_str):
        pass

    def update_tlv_element(self, tlv_element, dict):
        pass

    def insert_tag(self, path, tag, value):
        pass

    def create_tlv_element(self, tag_class, tag_type):
        pass

    def encode(self):
        result = bytes()
        for _, tlv_element in self.tlv_elements.items():
            result += tlv_element.encode()
        return result

    def get_as_list(self, tlv_element=None):
        root_tag = self.__wrap_with_dummy_tag()
        if not root_tag:
            return ""
        return root_tag.get_as_list()

    def get_as_dict(self, tlv_element=None):
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
        pass

    def get_as_json(self):
        pass


if __name__ == "__main__":
    ber_tlv_parser = BerTlvParser()
    tag_parsed = ber_tlv_parser.parse_tlv()
    print(f"\nAll tag as hex str: {tag_parsed.get_as_hex_str()}")
