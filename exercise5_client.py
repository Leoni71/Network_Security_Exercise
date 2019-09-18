import asyncio
import sys
import playground

class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.transport = transport
        self.transport.write("<EOL>\n".encode())

    def data_received(self, data):
        print(data.decode('utf-8'))
        self.transport.write(input(">> ").encode('utf-8'))

def main(args):
    # client class 
    loop = asyncio.get_event_loop()
    coro = playground.create_connection(EchoClient,'20194.0.0.19000',19005)
    client = loop.run_until_complete(coro)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

    client.close()
    loop.run_until_complete(client.close())
    loop.close()

if __name__=="__main__":
    main(sys.argv[1:])