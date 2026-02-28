###############################################################################
# CS 255
# 1/12/25
# 
# messenger.py
# ______________
# Please implement the functions below according to the assignment spec
###############################################################################
from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hmac_to_hmac_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    gov_encryption_data_str
)

class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes, gov_public_key: bytes):
        """
        The certificate authority DSA public key is used to
        verify the authenticity and integrity of certificates
        of other users (see handout and receive_certificate)
        """
        # Feel free to store data as needed in the objects below
        # and modify their structure as you see fit.
        self.ca_public_key = cert_authority_public_key
        self.gov_public_key = gov_public_key
        self.conns = {}  # data for each active connection
        self.certs = {}  # certificates of other users
        self.username = None
        self.long_term_keypair = None

    def _get_conn_state(self, name: str) -> dict:
        if name not in self.conns:
            self.conns[name] = {"seen_headers": set()}
        return self.conns[name]


    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username".

        Inputs:
            username: str

        Returns:
            certificate: dict
        """
        self.username = username
        self.long_term_keypair = generate_eg()
        certificate = {
            "username": username,
            "public_key": self.long_term_keypair["public"],
        }
        return certificate


    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate.

        Inputs:
            certificate: dict
            signature: bytes

        Returns:
            None
        """
        cert_str = str(certificate)
        if not verify_with_ecdsa(self.ca_public_key, cert_str, signature):
            raise ValueError("Tampering detected!")

        username = certificate["username"]
        self.certs[username] = certificate


    def send_message(self, name: str, plaintext: str) -> tuple[dict, tuple[bytes, bytes]]:
        """
        Generate the message to be sent to another user.

        Inputs:
            name: str
            plaintext: str

        Returns:
            (header, ciphertext): tuple(dict, tuple(bytes, bytes))
        """
        recipient_cert = self.certs[name]
        recipient_public_key = recipient_cert["public_key"]

        sender_ephemeral_keypair = generate_eg()
        shared_secret = compute_dh(
            sender_ephemeral_keypair["private"],
            recipient_public_key,
        )
        salt = gen_random_salt()
        _, message_key = hkdf(shared_secret, salt, "message-key")

        gov_ephemeral_keypair = generate_eg()
        gov_shared_secret = compute_dh(
            gov_ephemeral_keypair["private"],
            self.gov_public_key,
        )
        gov_key = hmac_to_aes_key(gov_shared_secret, gov_encryption_data_str)
        iv_gov = gen_random_salt()
        receiver_iv = gen_random_salt()

        header = {
            "v_sender": sender_ephemeral_keypair["public"],
            "salt": salt,
            "v_gov": gov_ephemeral_keypair["public"],
            "iv_gov": iv_gov,
            "c_gov": encrypt_with_gcm(gov_key, message_key, iv_gov),
            "receiver_iv": receiver_iv,
        }
        ciphertext = encrypt_with_gcm(message_key, plaintext, receiver_iv, str(header))
        return header, ciphertext


    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.

        Inputs:
            name: str
            message: tuple(dict, tuple(bytes, bytes))

        Returns:
            plaintext: str
        """
        header, ciphertext = message
        conn_state = self._get_conn_state(name)
        header_id = (header["v_sender"], header["receiver_iv"])
        if header_id in conn_state["seen_headers"]:
            raise ValueError("Replay detected!")

        shared_secret = compute_dh(self.long_term_keypair["private"], header["v_sender"])
        _, message_key = hkdf(shared_secret, header["salt"], "message-key")
        plaintext = decrypt_with_gcm(
            message_key,
            ciphertext,
            header["receiver_iv"],
            str(header),
        )
        conn_state["seen_headers"].add(header_id)
        return plaintext
