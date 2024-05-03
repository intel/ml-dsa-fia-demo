# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: MIT

from termcolor import cprint
from tqdm import tqdm

from helper import DILITHIUM, PK_FILE_PATH, SIG_FILE_PATH, SIGS_FILE_PATH, load_pk, \
    load_msg_and_sig, load_msgs_and_sigs, get_color


class Verifier:
    def __init__(self) -> None:
        self.pk = None

    def verify(self, msg: bytes, sig: bytes, display_result: bool = True) -> bool:
        """
        Verifies whether the provided signature is a valid signature for the provided message.

        Args:
            msg: The message that was signed.
            sig: The signature to be verified.
            display_result: Whether to display the result of the verification.

        Returns:
            A Boolean value indicating whether the signature was successfully verified.
        """
        result = DILITHIUM.verify(self.pk, msg, sig)
        if display_result:
            m = msg.decode('utf-8')
            if len(m) > 25:
                m = m[0:25] + '...'
            cprint(f'verify(msg="{m}", sig="{sig.hex()[0:10]}..."): {result}', get_color(result))
        return result

    def verify_sigs(self, msgs: list[bytes], sigs: list[bytes], display_result: bool = False) -> bool:
        """
        Verifies whether the provided list of signatures contains valid signatures for messages in the provided list of
        messages.

        Args:
            msgs: The list of messages that were signed.
            sigs: The list of signatures to be verified.
            display_result: Whether to display the result of the verification.

        Returns:
            A Boolean value indicating whether the signatures were successfully verified. Returns at the first
            verification failure.
        """
        for msg, sig in tqdm(zip(msgs, sigs), total=len(msgs), desc=f'Verifying {len(msgs)} signatures'):
            result = self.verify(msg, sig, display_result)
            if not result and not display_result:
                m = msg.decode('utf-8')
                cprint(f'verify(msg="{m}", sig="{sig.hex()[0:10]}..."): {result}', self.__get_color(result))
                return result
        cprint(f'Successfully verified {len(msgs)} signatures!', get_color(True))
        return True

    def load_pk(self, pk_file_path: str = PK_FILE_PATH) -> None:
        """
        Loads a Dilithium public key from a JSON (JavaScript Object Notation) file.

        Args:
            pk_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
            Dilithium public key.

        Returns:
            A Dilithium public key.
        """
        self.pk = load_pk(pk_file_path)

    @staticmethod
    def load_sig(sig_file_path: str = SIG_FILE_PATH) -> tuple[bytes, bytes]:
        """
        Loads a message and a signature from a JSON (JavaScript Object Notation) file.

        Args:
            sig_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load a
            message and a signature.

        Returns:
            A message and a signature.
        """
        return load_msg_and_sig(sig_file_path)

    def load_sigs(self, sigs_file_path: str = SIGS_FILE_PATH) -> tuple[bytes, bytes]:
        """
        Loads a list of messages and the corresponding list of signatures from a JSON (JavaScript Object Notation) file.

        Args:
            sigs_file_path: The path to and the name of the JSON (JavaScript Object Notation) file from where to load
            the a list of messages and the corresponding list of signatures.

        Returns:
            A list of messages and a list of corresponding signatures.
        """
        return load_msgs_and_sigs(sigs_file_path)


if __name__ == '__main__':
    verifier = Verifier()
    verifier.load_pk()

    msg, sig = verifier.load_sig()
    verifier.verify(msg, sig)

    msg = b'Message X'
    verifier.verify(msg, sig)
