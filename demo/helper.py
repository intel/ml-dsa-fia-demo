# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: MIT

from functools import partial
import json
import os
import sys
from termcolor import cprint

base_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(base_dir, "../dilithium-py"))

from dilithium import Dilithium2, Dilithium3, Dilithium5

# Set the security level of Dilithium (Dilithium2, Dilithium3 or Dilithium5)
DILITHIUM = Dilithium2

PK_FILE_PATH = os.path.join(base_dir, 'data/pk.json')
SK_FILE_PATH = os.path.join(base_dir, 'data/sk.json')
SIG_FILE_PATH = os.path.join(base_dir, 'data/sig.json')
SIGS_FILE_PATH = os.path.join(base_dir, 'data/sigs.json')
FAULTY_SIG_FILE_PATH = os.path.join(base_dir, 'data/faulty_sig.json')
FAULTY_SIGS_FILE_PATH = os.path.join(base_dir, 'data/faulty_sigs.json')
S1_HASH_FILE_PATH = os.path.join(base_dir, 'data/s1_hash.json')

S1_HASH_LENGTH = 256

info = partial(cprint, color='blue')


def get_color(correct: bool) -> str:
    """
    Gets a color name depending on the value of the provided parameter.

    Args:
        correct: The parameter used to select a color (True -> green, False -> red).

    Returns:
        A color name.
    """
    if correct:
        return 'green'
    else:
        return 'red'



def __json_dump_data(data: dict[str, str], file_path: str) -> None:
    """
    Dumps a dictionary to a JSON (JavaScript Object Notation) file.

    Args:
        data: The dictionary to be dumped to the JSON (JavaScript Object Notation) file.
        file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to dump the dictionary.

    Raises:
        FileNotFoundError: If file_path was not found.
        Exception: If any other exception.

    Returns:
        None.
    """
    try:
        with open(file_path, 'w') as file:
            json.dump(data, file, indent=' ' * 4)
    except FileNotFoundError:
        print('Error: The specified file could not be found.')
    except Exception as e:
        print(f'An unexpected error occurred: {e}')


def __json_load_data(file_path: str) -> dict[str, str]:
    """
    Loads a dictionary from a JSON (JavaScript Object Notation) file.

    Args:
        file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load the
        dictionary.

    Raises:
        FileNotFoundError: If file_path was not found.
        Exception: If any other exception.

    Returns:
        A dictionary.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print('Error: The specified file could not be found.')
    except Exception as e:
        print(f'An unexpected error occurred: {e}')


def save_pk(pk: bytes, pk_file_path: str = PK_FILE_PATH) -> None:
    """
    Saves the provided Dilithium public key to a JSON (JavaScript Object Notation) file.

    Args:
        pk: The public key to be saved to a JSON (JavaScript Object Notation) file.
        pk_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the provided
        Dilithium public key.

    Returns:
        None.
    """
    rho, t1 = DILITHIUM._unpack_pk(pk)

    t1_bytes = t1.bit_pack_t1()

    pk_data = {'rho': rho.hex(),
               't1': t1_bytes.hex()}

    __json_dump_data(pk_data, pk_file_path)


def load_pk(pk_file_path: str = PK_FILE_PATH) -> bytes:
    """
    Loads a Dilithium public key from a JSON (JavaScript Object Notation) file.

    Args:
        pk_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
        Dilithium public key.

    Returns:
        A Dilithium public key.
    """
    pk_data = __json_load_data(pk_file_path)

    rho = bytes.fromhex(pk_data['rho'])
    t1 = bytes.fromhex(pk_data['t1'])
    pk_bytes = rho + t1

    return DILITHIUM._pack_pk(*DILITHIUM._unpack_pk(pk_bytes))


def save_sk(sk: bytes, sk_file_path: str = SK_FILE_PATH) -> None:
    """
    Saves the provided Dilithium secret key to a JSON (JavaScript Object Notation) file.

    Args:
        sk: The Dilithium secret key to be saved to a JSON (JavaScript Object Notation) file.
        sk_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the provided
        Dilithium secret key.

    Returns:
        None.
    """
    rho, K, tr, s1, s2, t0 = DILITHIUM._unpack_sk(sk)

    s1_bytes = s1.bit_pack_s(DILITHIUM.eta)
    s2_bytes = s2.bit_pack_s(DILITHIUM.eta)
    t0_bytes = t0.bit_pack_t0()

    sk_data = {'rho': rho.hex(),
               'K': K.hex(),
               'tr': tr.hex(),
               's1': s1_bytes.hex(),
               's2': s2_bytes.hex(),
               't0': t0_bytes.hex()}

    __json_dump_data(sk_data, sk_file_path)


def load_sk(sk_file_path: str = SK_FILE_PATH) -> bytes:
    """
    Loads a Dilithium secret key from a JSON (JavaScript Object Notation) file.

    Args:
        sk_file_path: the path to and the name of the JSON (JavaScript Object Notation) file from where to load a
        Dilithium secret key.

    Returns:
        The Dilithium secret key.
    """
    sk_data = __json_load_data(sk_file_path)

    rho = bytes.fromhex(sk_data['rho'])
    K = bytes.fromhex(sk_data['K'])
    tr = bytes.fromhex(sk_data['tr'])
    s1 = bytes.fromhex(sk_data['s1'])
    s2 = bytes.fromhex(sk_data['s2'])
    t0 = bytes.fromhex(sk_data['t0'])
    sk_bytes = rho + K + tr + s1 + s2 + t0

    return DILITHIUM._pack_sk(*DILITHIUM._unpack_sk(sk_bytes))


def save_s1_hash(s1_hash: bytes, s1_hash_file_path: str = S1_HASH_FILE_PATH) -> None:
    """
    Saves the hash of secret vector s1 to a JSON (JavaScript Object Notation) file.

    Args:
        s1_hash: The hash of the secret vector s1.
        s1_hash_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the
        provided hash of a secret vector s1.

    Returns:
        None.
    """
    s1_hash_data = {'s1_hash': s1_hash.hex()}
    __json_dump_data(s1_hash_data, s1_hash_file_path)


def load_s1_hash(s1_hash_file_path: str = S1_HASH_FILE_PATH) -> bytes:
    """
    Loads a hash of a secret vector s1 from a JSON (JavaScript Object Notation) file.

    Args:
        s1_hash_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
        hash of a secret vector s1.

    Returns:
        A hash of a secret vector s1.
    """
    s1_hash_data = __json_load_data(s1_hash_file_path)
    s1_hash_bytes = bytes.fromhex(s1_hash_data['s1_hash'])

    return s1_hash_bytes


def save_msg_and_sig(msg, sig, sig_file_path: str = SIG_FILE_PATH) -> None:
    """
    Saves the provided message and the provided corresponding signature in a JSON (JavaScript Object Notation) file.

    Args:
        msg: The message to be saved to a JSON (JavaScript Object Notation) file.
        sig: The signature to be saved to a JSON (JavaScript Object Notation) file.
        sig_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the
        provided message and the provided signature.

    Returns:
        None.
    """
    c_tilde, z, h = DILITHIUM._unpack_sig(sig)

    z_bytes = z.bit_pack_z(DILITHIUM.gamma_1)
    h_bytes = DILITHIUM._pack_h(h)

    sig_data = {'msg': msg.hex(),
                'c_tilde': c_tilde.hex(),
                'z': z_bytes.hex(),
                'h': h_bytes.hex()}

    __json_dump_data(sig_data, sig_file_path)


def load_msg_and_sig(sig_file_path: str = SIG_FILE_PATH) -> tuple[bytes, bytes]:
    """
    Loads a message and a corresponding signature from a JSON (JavaScript Object Notation) file.

    Args:
        sig_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
        message and a corresponding signature.

    Returns:
        A message and a corresponding signature.
    """
    sig_data = __json_load_data(sig_file_path)

    msg = bytes.fromhex(sig_data['msg'])
    c_tilde = bytes.fromhex(sig_data['c_tilde'])
    z = bytes.fromhex(sig_data['z'])
    h = bytes.fromhex(sig_data['h'])
    sig_bytes = c_tilde + z + h

    return msg, DILITHIUM._pack_sig(*DILITHIUM._unpack_sig(sig_bytes))


def save_msgs_and_sigs(msgs: bytes, sigs: bytes, sigs_file_path: str = SIGS_FILE_PATH) -> None:
    """
    Saves the provided list of messages and the provided list of corresponding signatures in a JSON (JavaScript Object
    Notation) file.

    Args:
        msgs: The list of messages to be saved to a JSON (JavaScript Object Notation) file.
        sigs: The list of signatures to be saved to a JSON (JavaScript Object Notation) file.
        sigs_file_path: The path to and the name of the JSON (JavaScript Object Notation) file where to save the
        provided list of messages and the provided list of corresponding signatures.

    Returns:
        None.
    """
    sigs_data = {}

    for i, (msg, sig) in enumerate(zip(msgs, sigs)):
        c_tilde, z, h = DILITHIUM._unpack_sig(sig)

        z_bytes = z.bit_pack_z(DILITHIUM.gamma_1)
        h_bytes = DILITHIUM._pack_h(h)

        sigs_data[i] = {'msg': msg.hex(),
                        'c_tilde': c_tilde.hex(),
                        'z': z_bytes.hex(),
                        'h': h_bytes.hex()}

    __json_dump_data(sigs_data, sigs_file_path)


def load_msgs_and_sigs(sigs_file_path: str = SIGS_FILE_PATH) -> tuple[list[bytes], list[bytes]]:
    """
    Loads a list of messages and a list of corresponding signatures from a JSON (JavaScript Object Notation) file.

    Args:
        sigs_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
        list of messages and a list of corresponding signatures.

    Returns:
        A list of messages and a list of corresponding signatures.
    """
    sigs_data = __json_load_data(sigs_file_path)

    msgs, sigs = [], []

    for _, sig_data in sigs_data.items():
        msg = bytes.fromhex(sig_data['msg'])
        c_tilde = bytes.fromhex(sig_data['c_tilde'])
        z = bytes.fromhex(sig_data['z'])
        h = bytes.fromhex(sig_data['h'])
        sig_bytes = c_tilde + z + h

        msgs.append(msg)
        sigs.append(DILITHIUM._pack_sig(*DILITHIUM._unpack_sig(sig_bytes)))

    return msgs, sigs


if __name__ == '__main__':
    pk, sk = DILITHIUM.keygen()

    msg1 = b'Message 1'
    sig1 = DILITHIUM.sign(sk, msg1)

    save_sk(sk)
    sk = load_sk()

    save_pk(pk)
    pk = load_pk()

    save_msg_and_sig(msg1, sig1)
    msg1, sig1 = load_msg_and_sig()

    assert DILITHIUM.verify(pk, msg1, sig1)

    msg2 = b'Message 2'
    sig2 = DILITHIUM.sign(sk, msg2)
    assert DILITHIUM.verify(pk, msg2, sig2)

    msg3 = b'Message 3'
    assert not DILITHIUM.verify(pk, msg3, sig2)
