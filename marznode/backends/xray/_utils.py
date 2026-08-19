"""xray utilities"""

import base64
import binascii
import re
import subprocess
from typing import Dict


# xray renamed these labels twice, and both renames matter to us:
#   <= v25.8.3   "Private key: X\nPublic key: Y"
#   >= v25.9.5   "PrivateKey: X\nPassword: Y\nHash32: Z"   (VLESS Encryption landed here)
#   >= v26.x     "PrivateKey: X\nPassword (PublicKey): Y\nHash32: Z"
# matching only the oldest form made get_x25519 return None on any modern core,
# which then blew up as a TypeError while resolving a REALITY inbound.
_X25519_OUTPUT = re.compile(
    r"Private ?[Kk]ey:\s*(?P<private>\S+)\s*\n"
    r"(?:Public ?[Kk]ey|Password(?: \(PublicKey\))?):\s*(?P<public>\S+)"
)


def get_version(xray_path: str) -> str | None:
    """
    get xray version by running its executable
    :param xray_path:
    :return: xray version
    """
    cmd = [xray_path, "version"]
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
    match = re.match(r"^Xray (\d+\.\d+\.\d+)", output)
    if match:
        return match.group(1)
    return None


def get_x25519(xray_path: str, private_key: str = None) -> Dict[str, str] | None:
    """
    get x25519 public key using the private key
    :param xray_path:
    :param private_key:
    :return: x25519 publickey
    """
    cmd = [xray_path, "x25519"]
    if private_key:
        cmd.extend(["-i", private_key])
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
    match = re.search(_X25519_OUTPUT, output)
    if match:
        private, public = match.group("private"), match.group("public")
        return {"private_key": private, "public_key": public}
    return None
