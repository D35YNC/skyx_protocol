import binascii
import hashlib
import hmac
from typing import Union


import Crypto.Cipher.AES as AES
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP
import Crypto.PublicKey.RSA as RSA
import Crypto.Random
import Crypto.Util.Padding

# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad

from protocol.packet_type import PacketType


class Packet(object):
    """Default packet. 'Wrapper' around of bytes that need send to endless network..."""
    HEADERS_LENGTH = 3

    def __init__(self, packet_type_: PacketType, data: Union[bytes, bytearray], data_encrypted: bool = False):
        self._packet_type = packet_type_
        self._data = data
        self._encrypted = data_encrypted

    def encrypt(self, key: Union[bytes, bytearray]):
        """Packet data encryption with AES and `key`. Adds a HMAC to the end of the data"""
        if self._encrypted:
            raise ValueError("Packet already encrypted")

        if len(key) != 32:
            raise ValueError("DUCK ALL KEYS < 256 bits =)")

        iv = Crypto.Random.get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        encrypted_data = cipher.encrypt(Crypto.Util.Padding.pad(self._data, AES.block_size))

        hmac_digest = hmac.new(key, encrypted_data, hashlib.sha3_256).digest()

        new_data = bytearray()
        new_data.extend(iv)
        new_data.extend(encrypted_data)
        new_data.extend(hmac_digest)

        self._data = new_data
        self._encrypted = True

    def decrypt(self, key: Union[bytes, bytearray]):
        """Packet data decryption with AES and `key`"""
        if not self._encrypted:
            raise ValueError("Packet already decrypted")

        if len(key) != 32:
            raise ValueError("DUCK ALL KEYS < 256 bits =)")

        iv = self._data[:16]
        hmac_digest = self._data[-32:]
        data = self._data[16:self._data.index(hmac_digest)]

        new_hmac_digest = hmac.new(key, data, hashlib.sha3_256).digest()
        if hmac_digest != new_hmac_digest:
            raise ValueError("BAD HMAC FUCK FUCK FUCJ HEROIN ERROR")

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        self._data = Crypto.Util.Padding.unpad(cipher.decrypt(data), AES.block_size)
        self._encrypted = False

    def encrypt_rsa(self, key: RSA.RsaKey):
        """
        Ооо блять я заебался писать на английском. Короче эта штука должна была делать что то вроде ПГП,
        но этож рса что с него взять.
        """
        if self._encrypted:
            raise ValueError("Packet already encrypted")

        cipher = PKCS1_OAEP.new(key)
        self._data = cipher.encrypt(self._data)
        self._encrypted = True

    def decrypt_rsa(self, key: RSA.RsaKey):
        if not self._encrypted:
            raise ValueError("Packet already decrypted")

        cipher = PKCS1_OAEP.new(key)
        self._data = cipher.decrypt(self._data)
        self._encrypted = False

    @staticmethod
    def from_bytes(buffer: Union[bytes, bytearray]):
        """"""
        return Packet(PacketType.from_byte(buffer[0]), buffer[Packet.HEADERS_LENGTH:], True)

    @property
    def is_encrypted(self) -> bool:
        """Is packet encrypted now?"""
        return self._encrypted

    @property
    def size(self) -> int:
        """Packet size in bytes (with headers)"""
        return self.HEADERS_LENGTH + len(self._data)

    @property
    def packet_type(self) -> PacketType:
        """Packet Type =)"""
        return self._packet_type

    @property
    def data(self) -> bytes:
        """Packet payload. `bytes` or `bytearray`"""
        return self._data

    def to_bytes(self) -> bytes:
        """Manually convert whole `Packet` to `bytes`"""
        return bytes(self)
        # return self.__bytes__()

    @classmethod
    def copy_packet(cls, packet):
        """Manually creates same Packet from `packet`"""
        return cls(packet.packet_type, packet.data, packet.is_encrypted)

    @staticmethod
    def pack_data(data: list[str]) -> bytes:
        """List[str] to bytes. Блять ну и хуйня =/"""
        return b"\xAA\xAA\xAA".join(x.encode() for x in data)

    @staticmethod
    def unpack_data(buffer: Union[bytes, bytearray]) -> list[str]:
        """`bytes` to List[str]"""
        return [x.decode() for x in buffer.split(b"\xAA\xAA\xAA")]

    def __str__(self):
        return f"Packet Type: {self._packet_type.name}; " \
               f"Data size: {len(self._data)}; " \
               f"Data encrypted: {self._encrypted}; " \
               f"Hex data: {binascii.hexlify(self._data).decode()}; " \
               f"Packet size: {self.size}"

    def __repr__(self):
        return f"protocol.Packet(protocol.{self._packet_type}, {self._data}, {self._encrypted})"

    def __bytes__(self):
        packet = bytearray()
        packet.append(int(self._packet_type))
        packet.extend(len(self._data).to_bytes(2, 'little'))
        if self._data:
            packet.extend(self._data)
        return bytes(packet)
