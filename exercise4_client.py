import asyncio
import sys

class EchoClient(asyncio.Protocol):
    def __init__(self):
        pass

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        print(data.decode('utf-8'))
        self.transport.write(input(">> ").encode('utf-8'))

def main(args):
    # client class 
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(EchoClient,'192.168.200.52',19004)
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