from inspect import signature
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


def get_private_key():
    try:
        with open("auth/_private_key.pem", mode="r", encoding="utf8") as key_file:
            private_key = serialization.load_pem_private_key(
                bytes(key_file.read(), encoding="utf8"), password=None
            )
        # public_key = private_key.public_key()
    except Exception as e:
        print(e)
    return private_key

def save_enc_file(filename, enc_file_data,start_time):
    enc_filename = "enc_recv_" + filename.split("/")[-1]
    with open(
        f"recv_files_enc/{enc_filename}", mode="wb"
    ) as fp:
        fp.write(enc_file_data)
    print(
        f"Finished saving ENCRYPTED file in {(time.time() - start_time)}s!"
    )

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()
            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()
                            private_key = get_private_key()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            enc_file_data = read_bytes(client_socket, file_len)

                            # Save to recv_files_enc
                            save_enc_file(filename, enc_file_data, start_time)
     
                            dec_file_data = session_key.decrypt(enc_file_data)
                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(dec_file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            print("Receiving authentication request message...")
                            start_time = time.time()

                            # 1. Receive message for authentication from client 
                            msg_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            message = read_bytes(client_socket, msg_len)

                            # 2. Sign message digest and send back to client
                            private_key = get_private_key()
                            signature = private_key.sign(
                                    message, # message in bytes format
                                    padding.PSS(
                                        mgf=padding.MGF1(hashes.SHA256()),
                                        salt_length=padding.PSS.MAX_LENGTH,
                                    ),
                                    hashes.SHA256(), # hashing algorithm used to hash the data before encryption
                                )
                            client_socket.sendall(convert_int_to_bytes(len(signature)))
                            client_socket.sendall(signature)

                            # Send the signed CSR to client
                            cert = "auth/server_signed.crt"
                            f = open("auth/server_signed.crt", "rb")
                            server_cert_raw = f.read()
                            client_socket.sendall(convert_int_to_bytes(len(server_cert_raw)))
                            # server_cert_raw_bytes = bytes(server_cert_raw, encoding="utf8")
                            client_socket.sendall(server_cert_raw)
                            print(
                                f"Message Digest and Signed Certificate sent!"
                            )
                        case 4:
                            # Receives session key
                            enc_sess_key_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            enc_sess_key = read_bytes(client_socket, enc_sess_key_len)
                            session_key_bytes = private_key.decrypt(enc_sess_key, padding.PKCS1v15())
                            session_key = Fernet(session_key_bytes) # instantiate a Fernet instance with key
                            print("Session Key successfully received!")
                            


    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
