import asyncio
import time
import playground

from playground.network.packet import PacketType
from autograder_ex6_packets import AutogradeStartTest
from autograder_ex6_packets import AutogradeTestStatus
from escape_room_packets import GameCommandPacket
from escape_room_packets import GameResponsePacket


class EchoClientProtocol(asyncio.Protocol):
    def __init__(self, loop):
        self.flag = 0
        self.loop = loop
        self.deserializer = PacketType.Deserializer()
        self.command_list = ["look mirror", "get hairpin", "unlock chest with hairpin", "open chest",
                             "get hammer in chest", "hit flyingkey with hammer", "get key", "unlock door with key",
                             "open door"]
        self.flag = 0

    def connection_made(self, transport):
        self.transport = transport
        packetClient = AutogradeStartTest()
        packetClient.name = "Jiawei Guo"
        packetClient.team = 4
        packetClient.email = "jguo57@jhu.edu"
        packetClient.port = 2345
        with open("escape_room_packets.py", "rb") as f:
            packetClient.packet_file = f.read()
        self.transport.write(packetClient.__serialize__())

    def data_received(self, data):
        self.deserializer.update(data)
        for clientPacket in self.deserializer.nextPackets():
            if isinstance(clientPacket, AutogradeTestStatus):
                print(clientPacket.client_status)
                print(clientPacket.server_status)
                print(clientPacket.error)

            if isinstance(clientPacket, GameResponsePacket):
                res_temp = clientPacket.res
                print(clientPacket.res)
                if self.flag <= len(self.command_list) - 1:
                    if res_temp.split()[-1] == "wall" or res_temp.split()[-1] == "floor" or res_temp.split()[-1] == "ceiling":
                        continue
                    if res_temp == "You can't hit that!":
                        self.flag = self.flag - 1
                        game_packet = GameCommandPacket()
                        command = game_packet.create_game_command_packet(self.command_list[self.flag])
                        self.transport.write(command.__serialize__())
                        print(self.command_list[self.flag])
                        self.flag = self.flag + 1
                    else:
                        game_packet = GameCommandPacket()
                        command = game_packet.create_game_command_packet(self.command_list[self.flag])
                        self.transport.write(command.__serialize__())
                        print(self.command_list[self.flag])
                        self.flag = self.flag + 1
                time.sleep(1)

    def connection_lost(self, exc):
        print('The server closed the connection')
        print('Stop the event loop')
        self.loop.stop()


loop = asyncio.get_event_loop()
loop.set_debug(enabled=True)
# from playground.common.logging import EnablePresetLogging, PRESET_DEBUG
# EnablePresetLogging(PRESET_DEBUG)
coro = playground.create_connection(lambda: EchoClientProtocol(loop), '20194.0.0.19000', 19006)
# coro = loop.create_connection(lambda: EchoClientProtocol(loop), 'localhost', 1024)
loop.run_until_complete(coro)
loop.run_forever()
loop.close()
