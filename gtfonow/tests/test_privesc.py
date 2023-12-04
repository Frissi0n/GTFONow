from __future__ import print_function
import sys
import pytest
import os
from gtfonow.gtfonow import *
log.set_level(logging.DEBUG)

if sys.version_info >= (3, 3):
    from unittest.mock import MagicMock, patch
else:
    from mock import MagicMock, patch


def test_check_suid_bins():
    log.debug(os.getenv('PATH'))

    expected = {
        "Binary": "find",
        "Path": "/usr/bin/find",
        "Payload": suid_bins["find"][0]["code"],
        "Payload Description": suid_bins["find"][0].get("description"),
        "Type": "SUID/SGID Binary",
        "SUID": "root",
        "SGID": None,
        "Payload Type": "Shell"

    }

    res = check_suid_bins()
    assert expected in res


def test_check_sudo_nopasswd_binaries():
    log.debug(os.getenv('PATH'))

    sudo_l_output = get_sudo_l_output()
    res = check_sudo_nopasswd_binaries(sudo_l_output)
    expected = {
        "SudoUser": "root",
        "Binary": "head",
        "Path": "/usr/bin/head",
        "Payload": sudo_bins["head"][0]["code"],
        "Payload Description": sudo_bins["head"][0].get("description"),
        "Type": "Sudo NOPASSWD",
        "Payload Type": "Arbitrary read"

    }
    assert expected in res


PROOF_COMMAND = "cat /root/proof.txt"
test_cases = [
    ('head', sudo_bins["head"][0]["code"], SUDO_NO_PASSWD,
     2, True, '/usr/bin/head', PROOF_COMMAND),
    ('find', suid_bins["find"][0]["code"], SUID_SGID,
     2, True, '/usr/bin/find', PROOF_COMMAND),
    ('dd', suid_bins["dd"][0]["code"], SUID_SGID,
     2, True, '/usr/bin/dd', PROOF_COMMAND),
    ('tee', suid_bins["tee"][0]["code"], SUID_SGID,
     2, True, '/usr/bin/tee', PROOF_COMMAND),
    # ('cp', suid_bins["cp"][0]["code"], SUID_SGID,
    #  2, True, '/usr/bin/cp', PROOF_COMMAND),
    # ('mv', suid_bins["mv"][0]["code"], SUID_SGID,
    #  2, True, '/usr/bin/mv', PROOF_COMMAND),
]


@pytest.mark.parametrize("binary, payload, exploit_type, risk, auto, binary_path, command", test_cases)
def test_exploit(capsys,  binary, payload, exploit_type, risk, auto, binary_path, command):
    log.debug(os.getenv('PATH'))

    sys.exit = MagicMock()
    sys.exit.return_value = 0
    exploit(binary, payload, exploit_type, risk, auto,
            binary_path=binary_path, command=command)
    captured = capsys.readouterr()
    assert "ONLY_ROOT_CAN_READ_THIS" in captured.out
