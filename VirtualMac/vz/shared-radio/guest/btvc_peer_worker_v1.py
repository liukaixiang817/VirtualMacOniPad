"""Guest-local generic LE protocol worker; only the private host endpoint.

No RF access or device-specific profile selection. Physical radio operations
remain in the iPad owner. Protocol values/keys never enter diagnostic logs.
"""
import argparse
import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
import plistlib
import stat
import struct
import tempfile
import uuid
import sys

from bumble.keys import KeyStore, PairingKeys
from btvc_gatt_peer_v1 import BTVCGattPeerV1


class _PipeWriterProtocol(asyncio.streams.FlowControlMixin):
    def __init__(self, loop):
        super().__init__(loop=loop)
        self.closed = loop.create_future()

    def connection_lost(self, exc):
        super().connection_lost(exc)
        if not self.closed.done():
            self.closed.set_result(None)

    def _get_close_waiter(self, stream):
        return self.closed


class PrivateKeyStoreV1(KeyStore):
    def __init__(self, directory, identity):
        self.directory = Path(directory)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError("invalid private bond directory")
        self.path = self.directory / (hashlib.sha256(identity).hexdigest() + ".json")
        self.keys = {}
        try:
            fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 1048576:
                raise PermissionError("invalid private bond file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                document = json.load(stream)
            if document.get("schema") != 1 or len(document.get("keys", {})) > 256:
                raise ValueError("invalid private bond schema")
            self.keys = {name: PairingKeys.from_dict(value) for name, value in document["keys"].items()}
        finally:
            os.close(fd)

    def _save(self):
        fd, name = tempfile.mkstemp(prefix=".bond-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump({"schema": 1, "keys": {name: keys.to_dict() for name, keys in self.keys.items()}}, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name):
                os.unlink(name)

    async def update(self, name, keys):
        if name not in self.keys and len(self.keys) >= 256:
            raise ValueError("bond store full")
        self.keys[name] = keys
        self._save()

    async def get(self, name):
        return self.keys.get(name)

    async def get_all(self):
        return list(self.keys.items())

    async def delete(self, name):
        self.keys.pop(name, None)
        self._save()


class WorkerV1:
    def __init__(self, state):
        self.state = state
        self.sessions = {}
        self.pending = {}
        self.sequence = 0
        self.output = asyncio.Queue(maxsize=512)
        self.live = True

    def send(self, message):
        if not self.live:
            return
        body = plistlib.dumps(message, fmt=plistlib.FMT_BINARY, sort_keys=False)
        if not 0 < len(body) <= 65536:
            raise ValueError("worker message too large")
        self.output.put_nowait(struct.pack("!I", len(body)) + body)

    async def write(self, writer):
        while self.live:
            frame = await self.output.get()
            writer.write(frame)
            await writer.drain()

    async def operation(self, session, request):
        if session not in self.sessions or len(self.pending) >= 64:
            raise RuntimeError("peer operation unavailable")
        self.sequence += 1
        identifier = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = (session, future)
        try:
            self.send({"kind": "operation", "session": session, "request": identifier, "operation": request})
            result = await asyncio.wait_for(future, 90 if request.get("operation") == "pair" else 23)
            if request.get("operation") == "pair":
                print("VM27PeerWorker physicalPairResult ok=" + str(int(result.get("ok") is True)) +
                    " error=" + str(result.get("error", 0)) + " nativeError=" + str(result.get("nativeError", 0)), file=sys.stderr, flush=True)
            return result
        finally:
            self.pending.pop(identifier, None)

    def close(self, session, tell_host=True):
        peer = self.sessions.pop(session, None)
        if peer is None:
            return
        for identifier, (owner, future) in tuple(self.pending.items()):
            if owner == session and not future.done():
                future.cancel()
        peer.close()
        if tell_host:
            self.send({"kind": "close", "session": session})

    async def message(self, message):
        if not isinstance(message, dict):
            raise ValueError("invalid worker message")
        kind, session = message.get("kind"), message.get("session")
        if kind == "ready" and message.get("schema") == 1:
            print("VM27PeerWorker ready LE=1 classic=0 audio=0", file=sys.stderr, flush=True)
            return
        if not isinstance(session, str) or str(uuid.UUID(session)).upper() != session.upper():
            raise ValueError("invalid peer session")
        if kind == "open":
            if session in self.sessions or len(self.sessions) >= 16:
                raise ValueError("peer session limit")
            peripheral, central = message["peripheral"], message["central"]
            if not isinstance(peripheral, bytes) or not isinstance(central, bytes):
                raise ValueError("invalid peer addresses")
            keys = PrivateKeyStoreV1(self.state, peripheral + central)
            peer = BTVCGattPeerV1(lambda packet: self.send({"kind": "packet", "session": session, "packet": packet}),
                lambda request: self.operation(session, request), lambda: self.close(session), keys)
            self.sessions[session] = peer
            try:
                await peer.start(peripheral, central, message["metadata"])
            except Exception as error:
                print("VM27PeerWorker linkRejected type=" + type(error).__name__, file=sys.stderr, flush=True)
                self.close(session)
                return
            self.send({"kind": "opened", "session": session})
            print("VM27PeerWorker generic LE session opened", file=sys.stderr, flush=True)
        elif kind == "close":
            self.close(session, tell_host=False)
        elif kind == "packet" and session in self.sessions:
            try:
                self.sessions[session].feed(message["packet"])
            except Exception as error:
                print("VM27PeerWorker linkRejected type=" + type(error).__name__, file=sys.stderr, flush=True)
                self.close(session)
        elif kind == "result":
            item = self.pending.get(message.get("request"))
            if item and item[0] == session and not item[1].done():
                result = message.get("result")
                if not isinstance(result, dict):
                    raise ValueError("invalid backend result")
                item[1].set_result(result)
        elif kind == "notification" and session in self.sessions:
            event = message["event"]
            if event.get("event") == "value":
                await self.sessions[session].notification(event["attribute"], event["value"])
        elif kind == "pairingChallenge":
            # Guest UI integration is required for PIN/numeric-comparison
            # challenges. Keep the physical prompt pending and reject timeout;
            # never silently approve it or substitute a default passkey.
            print("VM27PeerWorker guest pairing interaction required", file=sys.stderr, flush=True)

    async def run(self, reader, writer):
        self.send({"kind": "hello", "schema": 1})
        writing = asyncio.create_task(self.write(writer))
        try:
            while self.live:
                length = struct.unpack("!I", await reader.readexactly(4))[0]
                if not 0 < length <= 65536:
                    raise ValueError("invalid worker frame")
                await self.message(plistlib.loads(await reader.readexactly(length)))
        finally:
            self.live = False
            for session in tuple(self.sessions):
                self.close(session, tell_host=False)
            writing.cancel()
            await asyncio.gather(writing, return_exceptions=True)
            writer.close()
            await writer.wait_closed()


async def main(state, stdio=False):
    # Dependency diagnostics can contain addresses, keys and GATT values.
    # Report only our own fixed state transitions and exception class names.
    logging.disable(logging.CRITICAL)
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda event_loop, context: print("VM27PeerWorker asynchronous operation failed", file=sys.stderr, flush=True))
    if stdio:
        reader = asyncio.StreamReader()
        reader_transport, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer)
        protocol = _PipeWriterProtocol(loop)
        transport, _ = await loop.connect_write_pipe(lambda: protocol, sys.stdout.buffer)
        writer = asyncio.StreamWriter(transport, protocol, reader, loop)
        try:
            await WorkerV1(state).run(reader, writer)
        except (OSError, EOFError, asyncio.IncompleteReadError):
            pass
        finally:
            reader_transport.close()
        return
    while True:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("10.0.2.4", 39030), 5)
            await WorkerV1(state).run(reader, writer)
        except (OSError, ValueError, EOFError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            print("VM27PeerWorker awaiting private host endpoint", file=sys.stderr, flush=True)
        await asyncio.sleep(3)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--stdio", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(main(args.state, args.stdio))
    except Exception:
        print("VM27PeerWorker stopped after protocol failure", file=sys.stderr, flush=True)
        raise SystemExit(1)
