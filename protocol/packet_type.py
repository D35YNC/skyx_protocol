import enum


class PacketType(enum.Enum):
    """Package type indicator in the package header"""
    SkyXHello = 0
    Event = 1
    Message = 5
    File = 6

    def __int__(self):
        return self.value

    @staticmethod
    def from_byte(byte):
        try:
            return PacketType(byte)
        except ValueError:
            return None
