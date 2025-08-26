# TLV-for-Everyone

A small, Python-based BER-TLV (Tag-Length-Value) parser and encoder, designed for EMV and smartcard-style data structures.  
It supports:

- Parsing TLV streams into a tree structure
- Constructed vs primitive tags
- Long-form and short-form lengths
- Nested TLVs inside constructed tags
- Round-trip encode/decode
- Case-insensitive tag lookup with simple path syntax (`find("9F02")`, `find("A0/5F2A")`)
- Dummy-root wrapper (`FF`) for multiple top-level siblings

---

## Installation

```bash
pip install tlv-for-everyone
```

## Usage

```python
from TlvParser.TlvParser import BerTlvParser, BerTlvElement

# Parse an EMV-like TLV string
data = "9F02060000000001009F1A0208405F2A020978"
parser = BerTlvParser()
tlv = parser.parse_tlv(data)

# Pretty-print as dict
print(tlv.get_as_dict())

# Find a tag
val = tlv.find("9F02").get_value_as_hex_str()
print("Amount:", val)
```


## Creating TLVs

```python

# Construct a TLV structure programmatically
parent = BerTlvElement(0xA0, {})
child1 = BerTlvElement(0x9A, bytes.fromhex("250826"))
child2 = BerTlvElement(0x5F2A, bytes.fromhex("0124"))
parent.add_child(child1)
parent.add_child(child2)

# Encode to bytes
encoded = parent.encode().hex().upper()
print("Encoded:", encoded)
```


## Running Tests

This project uses [pytest](https://docs.pytest.org/) and [hypothesis](https://hypothesis.readthedocs.io/).

```bash
pip install -r requirements-dev.txt
```


Run all tests:
```bash
pytest -v
```


## Development Roadmap

- Improve XML/JSON exporters
- Add support for indefinite-length encoding
- More robust error handling and diagnostics
- PyPI packaging


## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you’d like to change.


## License
MIT License. See LICENSE for details.