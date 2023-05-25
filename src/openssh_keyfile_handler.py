import base64
from typing import List, NamedTuple, Union

from cryptography.hazmat.backends.openssl.ed25519 import Ed25519PrivateKey, _Ed25519PrivateKey
from cryptography.hazmat.backends.openssl.rsa import RSAPrivateKey, _RSAPrivateKey

from src.ssh_agent import SshAgentError


class OpensshPublicKeyResult(NamedTuple):
    key_type: str
    public_keys: List[bytes]


class OpensshPrivateKeyResult(NamedTuple):
    key_type: str
    public_keys: List[bytes]
    private_keys: List[bytes]
    comment: str


class Keys(NamedTuple):
    key_type: str
    keys: List[Union[_Ed25519PrivateKey]]


def _openssh_public_key(data: bytes, number_of_keys: int) -> OpensshPublicKeyResult:
    tmp_data = data

    key_type_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    key_type = tmp_data[:key_type_len]
    tmp_data = tmp_data[key_type_len:]

    public_keys: List[bytes] = []
    for i in range(number_of_keys):
        if key_type == b"ssh-rsa":
            _key_type_len = int.from_bytes(tmp_data[:4], "big")
            tmp_data = tmp_data[4:]
            _key_type = tmp_data[:_key_type_len]
            tmp_data = tmp_data[_key_type_len:]

        public_key_len = int.from_bytes(tmp_data[:4], "big")
        tmp_data = tmp_data[4:]
        public_key = tmp_data[:public_key_len]
        tmp_data = tmp_data[public_key_len:]

        public_keys.append(public_key)

    if tmp_data:
        raise SshAgentError("There is not suppose to be left over data in the variable tmp_data")

    return OpensshPublicKeyResult(key_type=key_type.decode(), public_keys=public_keys)


def _openssh_private_key(data: bytes, number_of_keys: int) -> OpensshPrivateKeyResult:
    tmp_data = data

    random_32_bits_part_1 = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    random_32_bits_part_2 = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]

    key_type_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    key_type = tmp_data[:key_type_len]
    tmp_data = tmp_data[key_type_len:]

    public_keys: List[bytes] = []
    for i in range(number_of_keys):
        public_key_len = int.from_bytes(tmp_data[:4], "big")
        tmp_data = tmp_data[4:]
        public_key = tmp_data[:public_key_len]
        tmp_data = tmp_data[public_key_len:]

        public_keys.append(public_key)

    private_keys: List[bytes] = []
    for i in range(number_of_keys):
        private_key_len = int.from_bytes(tmp_data[:4], "big")
        tmp_data = tmp_data[4:]
        private_key = tmp_data[:private_key_len]
        tmp_data = tmp_data[private_key_len:]

        if private_key == "ssh-ed25519":
            if private_key.endswith(public_keys[i]):
                private_key = private_key[:-public_keys[i].__len__()]

        private_keys.append(private_key)

    comment_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    comment = tmp_data[:comment_len]
    tmp_data = tmp_data[comment_len:]

    # Verify Padding: aligning private key to the blocksize
    for i in range(tmp_data.__len__()):
        if tmp_data[i] != i+1:
            raise SshAgentError("Not able to verify Padding for private key")

    return OpensshPrivateKeyResult(
        key_type=key_type.decode(), public_keys=public_keys, private_keys=private_keys, comment=comment.decode())


# cat git.netic.dk_ed25519 | sed -n -e '/-BEGIN/,/-END/p' | sed  -e '/OPENSSH/d' | base64 -d | hexdump -C
def handle_begin_openssh_private_key(pem_format: bytes) -> Keys:
    # Remote begin and end of pem format
    base64_encode_data = b''.join(pem_format.split(b"\n")[1:-2])
    data = base64.b64decode(base64_encode_data)

    tmp_data = data
    identifier_len = tmp_data.index(b'\x00')
    identifier = tmp_data[:identifier_len]
    tmp_data = tmp_data[identifier_len+1:]  # +1, because, NULL-terminated string

    if identifier != b'openssh-key-v1':
        raise SshAgentError("Only support the protocol openssh-key: v1")

    cipher_name_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    cipher_name = tmp_data[:cipher_name_len]
    tmp_data = tmp_data[cipher_name_len:]

    kdf_name_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    kdf_name = tmp_data[:kdf_name_len]
    tmp_data = tmp_data[kdf_name_len:]

    kdf_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    kdf = tmp_data[:kdf_len]
    tmp_data = tmp_data[kdf_len:]

    number_of_keys = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]

    openssh_public_key_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    openssh_public_key = tmp_data[:openssh_public_key_len]
    tmp_data = tmp_data[openssh_public_key_len:]

    openssh_private_key_len = int.from_bytes(tmp_data[:4], "big")
    tmp_data = tmp_data[4:]
    openssh_private_key = tmp_data[:openssh_private_key_len]
    tmp_data = tmp_data[openssh_private_key_len:]

    if tmp_data:
        raise SshAgentError("There is not suppose to be left over data in the variable tmp_data")

    public_key_result = _openssh_public_key(openssh_public_key, number_of_keys=number_of_keys)
    private_key_result = _openssh_private_key(openssh_private_key, number_of_keys=number_of_keys)

    if public_key_result.key_type != private_key_result.key_type:
        raise SshAgentError(f"The public key type ({public_key_result.key_type}) "
                            f"is not the same as the private key type ({private_key_result.key_type})",
                            public_key_result.key_type, private_key_result.key_type)

    if private_key_result.public_keys != public_key_result.public_keys:
        raise SshAgentError(f"There are problems with the public keys",
                            private_key_result.public_keys, public_key_result.public_keys)

    if private_key_result.key_type == "ssh-ed25519":
        key_type = "ed25519"
        keys = [Ed25519PrivateKey.from_private_bytes(key) for key in private_key_result.private_keys]

    elif private_key_result.key_type == "ssh-rsa":
        key_type = "rsa"
        keys = []

    else:
        raise SshAgentError(f"There is no support for the key type: {private_key_result.key_type}")

    print(end="")
