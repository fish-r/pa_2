from inspect import getcallargs
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")

def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

def get_ca_public_key():
    f = open("auth/cacsertificate.crt", "rb")
    ca_cert_raw = f.read()
    ca_cert = x509.load_pem_x509_certificate(
    data=ca_cert_raw, backend=default_backend()
    )
    ca_public_key = ca_cert.public_key()
    return ca_public_key

def check_server_id(s):
    print("Verifying Server ID...")
    # ca public key for verifying the digest later
    # the CA's certificate is its public key: cacsertificate
    ca_public_key = get_ca_public_key()
    #original message
    message = "Client Request SecureStore ID"
    message_bytes = bytes(message, encoding="utf8")

    digest_len = convert_bytes_to_int(
        read_bytes(s, 8)
    )
    digest = read_bytes(s, digest_len)

    try:
        print("Verifying Signed Digest...")
        # 1. Verify signed digest with ca cert
        ca_public_key.verify(
            digest,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        server_signed_len = convert_bytes_to_int(
        read_bytes(s, 8)
        )
        server_cert_raw = read_bytes(s, server_signed_len)

        # 2. Verify server certificate with ca cert
        print("Verifying Server Certificate...")
        server_cert = x509.load_pem_x509_certificate(
        data=server_cert_raw, backend=default_backend()
        )
        ca_public_key.verify(
            signature=server_cert.signature, # signature bytes to  verify
            data=server_cert.tbs_certificate_bytes, # certificate data bytes that was signed by CA
            padding=padding.PKCS1v15(), # padding used by CA bot to sign the the server's csr
            algorithm=server_cert.signature_hash_algorithm,
        )
        
        assert server_cert.not_valid_before <= datetime.utcnow() <= server_cert.not_valid_after
        return True

    except Exception as e:
        print(e)
        print("ERROR: INVALID SIGNATURE")
        return False
        



def auth_request(s):
    print("Sending auth request...")
    message = "Client Request SecureStore ID"
    # send mode 3, then send message length and message itself
    message_bytes = bytes(message, encoding="utf8")

    s.sendall(convert_int_to_bytes(3))
    s.sendall(convert_int_to_bytes(len(message)))
    s.sendall(message_bytes)

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        while True:
            # authentication protocol
            auth_request(s)
            if not check_server_id(s):
                break
            
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
