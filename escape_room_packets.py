from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import STRING


class GameCommandPacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise6.gameclient"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("command_line", STRING),
    ]

    @classmethod
    def create_game_command_packet(cls, s):
        return cls(command_line = s)

    def command(self):
        return self.command_line


class GameResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "20194.exercise6.gameserver"
    DEFINITION_VERSION = "1.0"

    FIELDS = [
        ("res", STRING),
        ("sta", STRING),
    ]

    @classmethod
    def create_game_response_packet(cls, response, status):
        return cls(res=response, sta=status)

    def game_over(self):
        return self.sta != "playing"

    def status(self):
        return self.sta

    def response(self):
        return self.res
