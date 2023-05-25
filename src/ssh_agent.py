from typing import Optional, List, Any, Dict

import paramiko
import socket
import os
import time
import fcntl

from paramiko.common import io_sleep

from select import select
from threading import Thread
from .enum import RequestChan2Agent, ReplyAgent2Chan

jumpbox_addr = "ext-jump01.netic.dk"

jump_cmd = "ssh -T -o StrictHostKeyChecking=no -o LogLevel=ERROR patchme@srv-spl-idx02-p.aau.netic.dk check_ssh"
#jump_cmd = "check_ssh"

sock = "/tmp/ssh-F6vZ70EYkk0q/agent.17507"

test_print = None


def parse_msg(msg: bytes):
    size = int.from_bytes(msg[0:4], "big")
    msg_type = int(msg[4])
    data = msg[5:]

    #print(f"size: {size} - msg_type: {msg_type} - data_len: {len(data)}")

    return size, msg_type, data


def bytes2hex(b: bytes) -> str:
    s = b.hex()
    result = ""
    for i in range(len(s)):
        if (i + 1) % 8 == 0:
            result += s[i] + ' '
        else:
            result += s[i]

    return result


def request_parser(size: int, msg_type: RequestChan2Agent, data: bytes):
    pre_msg = "chan -> agent"
    tmp_data = data

    if msg_type == RequestChan2Agent.SSH_AGENTC_REQUEST_IDENTITIES:
        print(f"<-> {pre_msg}: Remote server requests identities from agent")

    if msg_type == RequestChan2Agent.SSH_AGENTC_SIGN_REQUEST:
        public_key_blob_len = int.from_bytes(tmp_data[0:4], "big")
        tmp_data = tmp_data[4:]

        public_key_blob = tmp_data[0:public_key_blob_len]
        tmp_data = tmp_data[public_key_blob_len:]

        data_len = int.from_bytes(tmp_data[0:4], "big")
        tmp_data = tmp_data[4:]

        data = tmp_data[0:data_len]
        tmp_data = tmp_data[data_len:]

        flags = int.from_bytes(tmp_data[0:4], "big")
        tmp_data = tmp_data[4:]

        print(
            f"    public_key_blob_len: {public_key_blob_len}\n"
            f"    public_key_blob: {public_key_blob.hex()}\n"
            f"    data_len: {data_len}\n"
            f"    data: {data.hex()}\n"
            f"    flags: {flags}"
        )

    else:
        print(f"<-> {pre_msg}: NOT_IMPLEMENTED_REPLY_PARSER_FOR: {msg_type.name}")

    if tmp_data:
        print(f"*** {pre_msg}: {bytes2hex(tmp_data)}")


def reply_parser(size: int, msg_type: ReplyAgent2Chan, data: bytes):
    pre_msg = "agent -> chan"
    tmp_data = data

    if msg_type == ReplyAgent2Chan.SSH_AGENT_IDENTITIES_ANSWER:
        number_of_identities = int.from_bytes(data[0:4], "big")
        tmp_data = tmp_data[4:]

        for i in range(number_of_identities):
            public_key_blob_len = int.from_bytes(tmp_data[0:4], "big")
            tmp_data = tmp_data[4:]

            public_key_blob = tmp_data[0:public_key_blob_len]
            tmp_data = tmp_data[public_key_blob_len:]

            fs_path_str_len = int.from_bytes(tmp_data[0:4], "big")
            tmp_data = tmp_data[4:]

            fs_path_str = tmp_data[0:fs_path_str_len].decode()
            tmp_data = tmp_data[fs_path_str_len:]
            print(
                f" {i}  number_of_identities: {number_of_identities}\n"
                f" {i}  public_key_blob_len: {public_key_blob_len}\n"
                f" {i}  public_key_blob: {public_key_blob.hex()}\n"
                f" {i}  fs_path_str_len: {fs_path_str_len}\n"
                f" {i}  fs_path_str: {fs_path_str}"
            )

    elif msg_type == ReplyAgent2Chan.SSH_AGENT_SIGN_RESPONSE:
        signature_len = int.from_bytes(tmp_data[0:4], "big")
        tmp_data = tmp_data[4:]

        signature = tmp_data[0:signature_len]
        tmp_data = tmp_data[signature_len:]

        print(
            f"    signature_len: {signature_len}\n"
            f"    signature: {signature.hex()}"
        )

    else:
        print(f"<-> {pre_msg}: NOT_IMPLEMENTED_REPLY_PARSER_FOR: {msg_type.name}")

    if tmp_data:
        print(f"*** {pre_msg}: {bytes2hex(tmp_data)}")


class _Tracker:
    def __init__(self):
        self.c2a_size = 0
        self.c2a_msg_type = None
        self.c2a_data = b''

        self.a2c_size = 0
        self.a2c_msg_type = None
        self.a2c_data = b''

    def chan2agent(self, b: bytes):
        pre_msg = "chan -> agent"

        if self.c2a_size == 0:
            size, msg_type, data = parse_msg(b)
            self.c2a_size = size
            self.c2a_msg_type = RequestChan2Agent(msg_type)
            self.c2a_data = data

        else:
            self.c2a_data += b

        if len(self.c2a_data) + 1 == self.c2a_size:
            self.c2a_size = 0
            print(f"=|= {pre_msg}: size({self.c2a_size}) - msg_type({self.c2a_msg_type}) - data_len({len(self.c2a_data)})")
            request_parser(self.c2a_size, self.c2a_msg_type, self.c2a_data)

    def agent2chan(self, b: bytes) -> str:
        pre_msg = "agent -> chan"

        if self.a2c_size == 0:
            size, msg_type, data = parse_msg(b)
            self.a2c_size = size
            self.a2c_msg_type = ReplyAgent2Chan(msg_type)
            self.a2c_data = data

        else:
            self.a2c_data += b

        if len(self.a2c_data) + 1 == self.a2c_size:
            self.a2c_size = 0
            print(f"=|= {pre_msg}: size({self.a2c_size}) - msg_type({self.a2c_msg_type}) - data_len({len(self.a2c_data)})")
            reply_parser(self.a2c_size, self.a2c_msg_type, self.a2c_data)


class DataTracker:
    _data: bytes

    def __init__(self):
        self._data = b''

    def empty(self) -> bool:
        if self._data:
            return False
        return True

    def len_known(self) -> bool:
        if self._data.__len__() >= 4:
            return True
        return False

    def add(self, data: bytes):
        self._data += data

    def all_data_received(self) -> bool:
        if self.len_known() and self._data_len == self._data.__len__() - 4:
            return True
        return False

    @property
    def _data_len(self) -> int:
        if self.len_known():
            return int.from_bytes(self._data[0:4], "big")
        return -1

    def fetch_data(self):
        tmp_data = self._data
        self._data = b''
        return tmp_data


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends.openssl import rsa, ed25519
import pem
from pem import OpenSSHPrivateKey, RSAPrivateKey, ECPrivateKey


class SshAgentError(BaseException):
    pass


class SshAgent:
    _exit: bool
    _thread: Optional[Thread]
    _channels: List[Any]
    _data: Dict[Any, DataTracker]

    def __init__(self):
        self._thread = None
        self._channels = []
        self._data = {}

    def add_ssh_key(self, pem_format: bytes):
        ssh_keys = pem.parse(pem_str=pem_format)

        for ssh_key in ssh_keys:
            ssh_key_type = type(ssh_key)

            if ssh_key_type == OpenSSHPrivateKey:
                pass

            elif ssh_key_type == RSAPrivateKey:
                pass

            elif ssh_key_type == ECPrivateKey:
                pass


    def start(self):
        if not (self._thread and self._thread.isAlive()):
            self._thread = Thread(group=None, target=self._run, name="SshAgent")
            self._exit = False
            self._thread.start()

        else:
            # TODO: log warning
            pass

    def stop(self):
        self._exit = True

    def running(self):
        if self._thread and self._thread.isAlive():
            return True
        return False

    def forward_agent_handler(self, channel) -> bool:
        if self.running():
            # Ref: https://man7.org/linux/man-pages/man2/fcntl.2.html

            # Get the file access mode and the file status flags of the channel
            old_flags = fcntl.fcntl(channel, fcntl.F_GETFL)

            # Set the file access mode and the file status, and add the O_NONBLOCK flag
            fcntl.fcntl(channel, fcntl.F_SETFL, old_flags | os.O_NONBLOCK)

            self._channels.append(channel)

            self._data[channel] = DataTracker()

            return True
        return False

    def _run(self):
        while not self._exit:
            events = select(self._channels, [], [], 0.5)
            for rlist, _wlist, _xlist in events:

                data_tracker = self._data[rlist]

                if data_tracker.empty() is True or data_tracker.len_known() is False:
                    data_tracker.add(rlist.recv(512))

                if data_tracker.all_data_received():
                    pass

                # if self.agent == fd:
                #     data = self.agent.recv(512)
                #     if len(data) != 0:
                #         self.tracker.agent2chan(data)
                #         self.chan.send(data)
                #     else:
                #         self._close()
                #         break
                # elif self.chan == fd:
                #     data = self.chan.recv(512)
                #     if len(data) != 0:
                #         self.tracker.chan2agent(data)
                #         self.agent.send(data)
                #     else:
                #         self._close()
                #         break
                # time.sleep(io_sleep)

        # Dump all the saved data
        self._data = {}

    def _close(self):
        self._exit = True
        self.chan.close()
        self.agent.close()
