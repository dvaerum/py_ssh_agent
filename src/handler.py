from .ssh_agent import SshAgent


_SSH_AGENT


def request_forward_agent_handler(chan_remote: paramiko.channel.Channel) -> bool:
    test_print = SshAgent(chan_remote)
    return True
