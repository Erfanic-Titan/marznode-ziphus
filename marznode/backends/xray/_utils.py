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

def get_mlkem768(xray_path: str, seed: str = None) -> Dict[str, str] | None:
    """
    get the ML-KEM-768 client key using the seed
    :param xray_path:
    :param seed:
    :return: ML-KEM-768 seed/client pair
    """
    cmd = [xray_path, "mlkem768"]
    if seed:
        cmd.extend(["-i", seed])
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
    match = re.search(r"Seed: (.+)\nClient: (.+)", output)
    if match:
        seed, client = match.groups()
        return {"seed": seed, "client": client}
    return None


def get_mldsa65(xray_path: str, seed: str = None) -> Dict[str, str] | None:
    """
    get the ML-DSA-65 verify key using the seed
    :param xray_path:
    :param seed:
    :return: ML-DSA-65 seed/verify pair
    """
    cmd = [xray_path, "mldsa65"]
    if seed:
        cmd.extend(["-i", seed])
    output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode("utf-8")
    match = re.search(r"Seed: (.+)\nVerify: (.+)", output)
    if match:
        seed, verify = match.groups()
        return {"seed": seed, "verify": verify}
    return None


def _split_decryption(decryption: str) -> tuple[str, str, str, list[str], list[str]] | None:
    """
    split a "decryption" value into (protocol, mode, ticket, padding, keys).

    padding segments are positional: everything between the ticket lifetime and
    the FIRST key is padding. a key is recognised by decoding to exactly 32
    bytes (X25519 private) or 64 bytes (ML-KEM-768 seed) - length, not a
    guess about how long padding tends to be.
    """
    parts = decryption.split(".")
    if len(parts) < 4 or parts[0] != "mlkem768x25519plus":
        return None
    if parts[1] not in ("native", "xorpub", "random"):
        return None
    if not parts[2]:
        return None

    padding: list[str] = []
    keys: list[str] = []
    for segment in parts[3:]:
        if keys:
            # once keys have started, every remaining segment must be a key
            if _key_size(segment) not in (32, 64):
                return None
            keys.append(segment)
            continue
        if _key_size(segment) in (32, 64):
            keys.append(segment)
        else:
            padding.append(segment)

    if not keys:
        return None
    return parts[0], parts[1], parts[2], padding, keys


def _key_size(segment: str) -> int | None:
    """decoded byte length of a base64(RawURL) segment, or None if not base64."""
    if not segment:
        return None
    try:
        return len(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, binascii.Error):
        return None


def derive_vless_encryption(xray_path: str, decryption: str) -> str | None:
    """
    derive the client-side "encryption" value from an inbound's "decryption".

    the two strings are structurally identical; only the third field differs
    (server states a ticket lifetime, client states 0rtt/1rtt) and each key is
    swapped for its public counterpart. this mirrors how the reality public key
    is derived from the inbound's private key.

    grammar (see xray's infra/conf/vless.go):
        mlkem768x25519plus . <native|xorpub|random> . <ticket> . <padding>... . <key>...

    the rtt mode is NOT a free choice: a server that states a ticket lifetime of
    "0s" issues no tickets, so the client must handshake every time and has to
    say 1rtt. hardcoding 0rtt produced a string that looked right and failed to
    connect against exactly those inbounds.

    :param xray_path:
    :param decryption: the inbound's "decryption" value
    :return: the client's "encryption" value, or None if not derivable
    """
    if not decryption or decryption == "none":
        return None

    split = _split_decryption(decryption)
    if not split:
        return None
    protocol, mode, ticket, padding, keys = split

    rtt = "1rtt" if ticket == "0s" else "0rtt"

    derived = [protocol, mode, rtt, *padding]
    for key in keys:
        size = _key_size(key)
        if size == 32:
            pair = get_x25519(xray_path, key)
            if not pair:
                return None
            derived.append(pair["public_key"])
        elif size == 64:
            pair = get_mlkem768(xray_path, key)
            if not pair:
                return None
            derived.append(pair["client"])
        else:
            return None

    return ".".join(derived)
