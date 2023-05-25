import unittest
from os import environ
from pathlib import Path
from typing import Optional

import paramiko

from .ssh_agent import SshAgent
from .openssh_keyfile_handler import handle_begin_openssh_private_key

ENV_TEST_SSH_HOST = "TEST_SSH_HOST"
ENV_TEST_SSH_PORT = "TEST_SSH_PORT"
ENV_TEST_SSH_USER = "TEST_SSH_USER"
ENV_TEST_SSH_KEY_PATH = "TEST_SSH_KEY_PATH"


class TestPatching(unittest.TestCase):
    host: str
    port: int
    user: str
    ssh_key_path: Path

    ssh_agent: Optional[SshAgent]

    @classmethod
    def setUpClass(cls) -> None:
        cls.host = environ.get(ENV_TEST_SSH_HOST)
        cls.port = int(environ.get(ENV_TEST_SSH_PORT, "22"))
        cls.user = environ.get(ENV_TEST_SSH_USER, environ.get("USER"))
        cls.ssh_key_path = Path(environ.get(ENV_TEST_SSH_KEY_PATH))

        if not (cls.host and cls.port and cls.ssh_key_path):
            raise EnvironmentError(f"The following environment variables need to be configured for unittest to work: "
                                   f"{ENV_TEST_SSH_HOST} & {ENV_TEST_SSH_KEY_PATH} & "
                                   f"{ENV_TEST_SSH_USER} (optional) {ENV_TEST_SSH_PORT} (optional)")

        if not cls.ssh_key_path.is_file():
            raise FileExistsError(f"The ssh_key_path does not exist: {cls.ssh_key_path}")

    def setUp(self) -> None:
        self.ssh_agent = SshAgent()

    def test_100_handle_begin_open_private_key(self):
        key1 = b'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAtoRjyWiwKNNKWTJo/sM6/Lq/P9Cq5mMqQ0evQo6LHmpwwO81B9AM\npPDXKWw3bTGD+PUTA3uU4ybmJLVtf7faZwiP6gRMLCfCzlBV9qEr4CDMExGposC5mbSdYi\n7Ssh4/7fmMV4NhwbQLQwvyuGgQLOtg3fcfnxO4ldGGr76BmJZUABs2drmsgFz73fwwGCZs\nu44loRrwxVF5ynWfEBRjEzW3swsG8EZrINh/yFXVIuFDtqnad/XHg2Tu+mmNmYe35S5pyk\n6B8Q/LLlyySaecXE9/hBG4YihZKLhnrQPLZlxWBxhzJC5FRDrmz/WqSBZ0+5liNsCTdDL5\nUKIC84OJswAAA9CGCAnghggJ4AAAAAdzc2gtcnNhAAABAQC2hGPJaLAo00pZMmj+wzr8ur\n8/0KrmYypDR69CjoseanDA7zUH0Ayk8NcpbDdtMYP49RMDe5TjJuYktW1/t9pnCI/qBEws\nJ8LOUFX2oSvgIMwTEamiwLmZtJ1iLtKyHj/t+YxXg2HBtAtDC/K4aBAs62Dd9x+fE7iV0Y\navvoGYllQAGzZ2uayAXPvd/DAYJmy7jiWhGvDFUXnKdZ8QFGMTNbezCwbwRmsg2H/IVdUi\n4UO2qdp39ceDZO76aY2Zh7flLmnKToHxD8suXLJJp5xcT3+EEbhiKFkouGetA8tmXFYHGH\nMkLkVEOubP9apIFnT7mWI2wJN0MvlQogLzg4mzAAAAAwEAAQAAAQBZjYPYowEsRt/H/DAA\nMJKUxpxoF16DREzMTjP0GDSya89/Gt+OQcqyc2le7bYUYaM7WCRIJS7cdY2enVZowDDtNQ\npH7Gvjjm7LBCfppxL8GZuID7aIIL/wZuqB7i97LdR4U2VE2zXv8QNFlms1h/nH0IXq4wIk\n72w2NmQ7fuHfl62MHeOcSlQgv+Wb4uHw3AFherix0fH62dDK7IAWRbKY7M/RCLDfRiQR5H\nIO1kz5ctoTIbLApvUw1XbnkjGmrB+dInK7XJkooHq22UVBHjcQKudl3sPEJAcrRir2lZ9K\nHT6oMVgsfPdicD/5eJbSoUO4WcE1HUae5tw2oSISNCEBAAAAgBXdn3wEQvVJbhgcQR/G6E\nGKyPN8xlxR62Sp07FUFdiPwpKlP1FKSOQ8WpK5sBKGJXQbDgzqXFNfl5IjnqJlfOsFCvlR\nRqYzrorxjRlEneG6qzjN58d9QbH7IsBIkPZ3rTiI5J54DFO0vRmi826GGRjKEpdCVjn8kH\n+Ifl4RoLSOAAAAgQDyElfnVRCAumUVxAgete0VPPD5SQsjRJPsQtTzVZmQmSvr0aTUjqAg\noVyKAAz+g6NURZ45AZjMa6e1ku0WzQYPpJ8vndVhbixKPutWUk/yd/XQv82VgxKKT/yShf\n6MMkiRjwEmVVVluzs2A5u7gsOgzUOcuy1SyFRdmg4lclxH4QAAAIEAwQTSsTpTN/opZg4q\nuxYhoaYyOKG6vzroEYU6ncIj4QptVlOndqACbFEdOOq0srQBj7t363NrfMQoSdPw0KhpiF\nVu5+eAs7AghgEFb8EtwSbLb4RN/ryA4CTVAQdMZ64iSFOpHT/Km5VLNQkrmKMO0lI2XC5d\nHl+GoNQOHJggtBMAAAAUZHZ2QEZhcm1lci1Cb3kubG9jYWwBAgMEBQYH\n-----END OPENSSH PRIVATE KEY-----\n'
        key2 = b'-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBAFz5Kci0iv0eHG21auzGaoy3gFoukgh41uwHbAjGMdwAAAJhuvlMSbr5T\nEgAAAAtzc2gtZWQyNTUxOQAAACBAFz5Kci0iv0eHG21auzGaoy3gFoukgh41uwHbAjGMdw\nAAAEAC0IiVpr0/AKGvXwczQhHh/Lv3MiZSz9DPMdK+VCxElUAXPkpyLSK/R4cbbVq7MZqj\nLeAWi6SCHjW7AdsCMYx3AAAAEGR2YWVydW1AdmFydW0uZGsBAgMEBQ==\n-----END OPENSSH PRIVATE KEY-----\n'

        test = handle_begin_openssh_private_key(key1)
        test = handle_begin_openssh_private_key(key2)
        print(end="")

    def test_500_login(self):
        with paramiko.SSHClient() as client:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, username=self.user)

            with client.get_transport() as jumpbox_transport:
                with jumpbox_transport.open_session() as channel:
                    channel.request_forward_agent(handler)
                    #agent = paramiko.agent.AgentRequestHandler(channel)

                    channel.set_combine_stderr(True)
                    channel.exec_command(jump_cmd)

                    data = b''
                    while True:
                        _data: bytes = channel.recv(1024)
                        if _data:
                            print(_data)
                            data += _data
                        else:
                            break

                    print(f"=== DONE ({channel.recv_exit_status()}) ===")
                    print(data)
