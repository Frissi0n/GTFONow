from gtfonow.gtfonow import *


def test_check_suid_bins():
    expected = {
        "Binary": "find",
        "Path": "/usr/bin/find",
        "Payloads": ['./find . -exec /bin/sh -p \\; -quit'],
        "Type": "SUID/SGID Binary",
        "SUID": "root",
        "SGID": None
    }

    res = check_suid_bins()
    # Assertions
    assert expected in res
