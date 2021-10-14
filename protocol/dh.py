import binascii
import hashlib

import Crypto.Random


class DiffieHellman(object):
    """ MY CUSTOM DIFFIE HELLMAN CLASS. There are many such classes, but this one is mine."""

    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g

        self.__private_key = int(binascii.hexlify(Crypto.Random.get_random_bytes(1024)), base=16)

    def generate_public_key(self) -> int:
        """Returns your first public key"""
        return pow(self.g, self.__private_key, self.p)

    def generate_intermediate_public_key(self, group_pub_key: int) -> int:
        """Return intermediate key for sending to next user"""
        return pow(group_pub_key, self.__private_key, self.p)

    def check_public_key(self, pub_key: int) -> bool:
        if 2 <= pub_key <= self.p - 2:
            if pow(pub_key, (self.p - 1) // 2, self.p) == 1:
                return True
        return False

    def generate_session_key(self, pub_key: int) -> bytes:
        """Return shared key for exchange users"""
        if self.check_public_key(pub_key):
            shared_key = pow(pub_key, self.__private_key, self.p)  # (((g^a)^b)^...^x)^me mod p
            return hashlib.sha3_256(str(shared_key).encode()).digest()
        else:
            raise ValueError("Bad public key from other party")
