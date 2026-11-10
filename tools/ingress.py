#!/usr/bin/env python3
"""TCP ingress to exactly one prepared Unix socket. Not a forward proxy."""
import argparse
import asyncio
import ipaddress
import json
from pathlib import Path


async def pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


async def run(config):
    if config.get('status') != 'target-approved':
        raise RuntimeError('Target not approved')
    address = str(ipaddress.ip_address(config['listen_host']))
    port = config['listen_port']
    if not isinstance(port, int) or not 1024 <= port <= 65535:
        raise ValueError('Explicit unprivileged listen_port required')
    async def handle(reader, writer):
        try:
            remote_reader, remote_writer = await asyncio.open_unix_connection(config['gateway_socket'])
            await asyncio.gather(pump(reader, remote_writer), pump(remote_reader, writer))
        except OSError:
            writer.close()
    server = await asyncio.start_server(handle, address, port)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(json.loads(args.config.read_text())))
