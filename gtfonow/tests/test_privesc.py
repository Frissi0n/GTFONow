from gtfonow.gtfonow import *


def test_check_suid_bins():
    expected = {
        "Binary": "find",
        "Path": "/usr/bin/find",
        "Payloads": suid_bins["find"],
        "Type": "SUID/SGID Binary",
        "SUID": "root",
        "SGID": None
    }

    res = check_suid_bins()
    # Assertions
    assert expected in res


def test_check_sudo_nopasswd_binaries():
    sudo_l_output = get_sudo_l_output()
    print(sudo_l_output)
    res = check_sudo_nopasswd_binaries(sudo_l_output)
    expected = {
        "Binary": "head",
        "Path": "/usr/bin/head",
        "Payloads": sudo_bins["head"],
        "SudoUser": "root",
        "Type": "Sudo NOPASSWD"

    }
    assert expected in res
