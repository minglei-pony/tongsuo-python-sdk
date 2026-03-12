#!/usr/bin/env python3
"""
Demo: TLCP (GB/T 38636-2020) client connection using tongsuopy.

This example demonstrates how to use tongsuopy's TLCP support to connect
to a TLCP server using the SM2/SM3/SM4 cipher suite.

"""

import socket

from tongsuopy.crypto.tlcp import SSLContext, create_default_context


def main():
    host = ""
    port = 443

    print("=== TLCP Client Demo ===")
    print(f"Connecting to {host}:{port} using TLCP (NTLSv1.1)...")
    print()

    # Method 1: Using create_default_context (simplest)
    print("--- Method 1: create_default_context ---")
    ctx = create_default_context(
        verify=False,
        ciphers="ECC-SM2-SM4-CBC-SM3",
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    with ctx.wrap_socket(sock, server_hostname=host) as tlcp_sock:
        print(f"  Protocol: {tlcp_sock.get_version()}")
        print(f"  Cipher:   {tlcp_sock.get_cipher()}")
        print("  Connected successfully!")
    print()

    # Method 2: Using SSLContext manually
    print("--- Method 2: SSLContext with manual configuration ---")
    ctx2 = SSLContext()
    ctx2.set_ciphers("ECC-SM2-SM4-CBC-SM3")
    ctx2.verify_mode = False

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(10)

    tlcp_sock = ctx2.wrap_socket(
        raw_sock,
        server_hostname=host,
        do_handshake_on_connect=False,
    )
    tlcp_sock.connect((host, port))

    print(f"  Protocol: {tlcp_sock.get_version()}")
    print(f"  Cipher:   {tlcp_sock.get_cipher()}")
    print("  Connected successfully!")
    tlcp_sock.close()
    print()

    print("=== All demos completed successfully! ===")


if __name__ == "__main__":
    main()
