import hashlib

import Crypto.PublicKey.RSA as RSA
from protocol.dh import DiffieHellman
from protocol.packet import Packet
from protocol.packet_type import PacketType


def do_handshake(socket, rsa_private_key):
    # server_pubkey_data = socket.recv(4096)
    # server_pubkey = RSA.import_key(server_pubkey_data)
    #?????
    server_pubkey_packet = receive_packet(socket)
    server_pubkey = RSA.import_key(server_pubkey_packet.data)

    # Send my PubKey
    socket.send(Packet(PacketType.SkyXHello, rsa_private_key.public_key().export_key()).to_bytes())

    return do_key_exchange(socket, rsa_private_key, [])


def do_key_exchange(socket, rsa_private_key, chain: list):
    """Key exchange magick here =)"""

    while len(chain) < 2:
        chain_packet = receive_packet(socket)
        if chain_packet:
            print("chain data", chain_packet.data)
            chain = Packet.unpack_data(chain_packet.data)
        if len(chain) < 2:
            print("Никого нет онлайн. Не с кем меняться ключами. Ждем")

    my_key_hash = hashlib.sha3_256(rsa_private_key.public_key().export_key()).hexdigest()
    my_index = chain.index(my_key_hash)

    # PHASESHIFT
    chain = chain[my_index:] + chain[:my_index]
    next_unit = chain[1]

    # print("Chain: ", "->".join(chain_to_readable(chain)))

    g = 2
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
    my_dh = DiffieHellman(p, g)
    group_dh_pubkey = my_dh.generate_public_key()

    socket.send(Packet(PacketType.SkyXHello, next_unit.encode() + group_dh_pubkey.to_bytes(512, 'big'), False).to_bytes())

    for i in range(len(chain) - 2):
        new_pk_packet = receive_packet(socket)
        other_pk = int.from_bytes(new_pk_packet.data[64:], 'big')
        group_dh_pubkey = my_dh.generate_intermediate_public_key(other_pk)
        socket.send(Packet(PacketType.SkyXHello, next_unit.encode() + group_dh_pubkey.to_bytes(512, 'big'), False).to_bytes())

    last_pk_packet = receive_packet(socket)
    other_pk = int.from_bytes(last_pk_packet.data[64:], 'big')

    return my_dh.generate_session_key(other_pk)


def receive_packet(socket):
    """Receive full packet from `socket`"""
    def header_from_bytes(buffer_):
        return PacketType.from_byte(buffer_[0]), int.from_bytes(buffer_[1:Packet.HEADERS_LENGTH], byteorder='little')

    buffer = socket.recv(Packet.HEADERS_LENGTH)
    if buffer:
        header = header_from_bytes(buffer)
        buffer += socket.recv(header[1])
        packet = Packet.from_bytes(buffer)
        return packet
    return None
