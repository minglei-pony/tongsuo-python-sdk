# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License. See the LICENSE file
# in the root of this repository for complete details.

"""
TLCP (GB/T 38636-2020) protocol support for tongsuopy.

This module provides SSLContext and SSLSocket classes to establish
TLCP connections using the Tongsuo library. TLCP is the Chinese
Transport Layer Cryptographic Protocol defined in GB/T 38636-2020.

Key features:
- NTLS (National TLS) protocol support via Tongsuo
- Double certificate support (sign cert/key + enc cert/key)
- SSLContext.wrap_socket() API compatible with Python's ssl module
"""

import socket
import ssl as _stdlib_ssl
import typing

from tongsuopy.backends.tongsuo.binding import Binding, _openssl_assert


def _decode_asn1_string(lib, ffi, asn1_str):
    """Decode an ASN1_STRING to a Python str using ASN1_STRING_to_UTF8."""
    buf_ptr = ffi.new("unsigned char **")
    length = lib.ASN1_STRING_to_UTF8(buf_ptr, asn1_str)
    if length < 0:
        # Fallback: read raw data
        data = lib.ASN1_STRING_get0_data(asn1_str)
        slen = lib.ASN1_STRING_length(asn1_str)
        if data == ffi.NULL or slen <= 0:
            return ""
        return ffi.buffer(data, slen)[:].decode("utf-8", errors="replace")
    try:
        return ffi.buffer(buf_ptr[0], length)[:].decode("utf-8")
    finally:
        lib.OPENSSL_free(buf_ptr[0])


def _parse_x509_name(lib, ffi, x509_name):
    """
    Parse an X509_NAME into the tuple-of-tuples format expected by
    Python's ssl module.

    Returns a tuple like:
        ((('commonName', 'example.com'),), (('organizationName', 'Org'),))

    Each RDN is a tuple of (attribute_name, value) tuples. For
    single-valued RDNs, each entry is a 1-tuple containing one pair.
    """
    result = []
    entry_count = lib.X509_NAME_entry_count(x509_name)
    for i in range(entry_count):
        entry = lib.X509_NAME_get_entry(x509_name, i)
        obj = lib.X509_NAME_ENTRY_get_object(entry)
        data = lib.X509_NAME_ENTRY_get_data(entry)

        nid = lib.OBJ_obj2nid(obj)
        if nid != lib.NID_undef:
            # Use the long name (e.g. "commonName", "organizationName")
            name_ptr = lib.OBJ_nid2ln(nid)
            attr_name = ffi.string(name_ptr).decode("ascii")
        else:
            # Use the short name as fallback
            name_ptr = lib.OBJ_nid2sn(nid)
            attr_name = ffi.string(name_ptr).decode("ascii")

        value = _decode_asn1_string(lib, ffi, data)
        # Each RDN is a 1-tuple of the (name, value) pair
        result.append(((attr_name, value),))

    return tuple(result)


def _parse_subject_alt_name(lib, ffi, x509):
    """
    Extract subjectAltName from an X509 certificate.

    Returns a tuple like:
        (('DNS', 'example.com'), ('DNS', '*.example.com'))

    Returns an empty tuple if no SAN extension is found.
    """
    san_entries = []
    ext_count = lib.X509_get_ext_count(x509)

    for i in range(ext_count):
        ext = lib.X509_get_ext(x509, i)
        ext_obj = lib.X509_EXTENSION_get_object(ext)
        ext_nid = lib.OBJ_obj2nid(ext_obj)

        if ext_nid != lib.NID_subject_alt_name:
            continue

        # Decode the extension to GENERAL_NAMES
        names = ffi.cast("GENERAL_NAMES *", lib.X509V3_EXT_d2i(ext))
        if names == ffi.NULL:
            continue

        try:
            num_names = lib.sk_GENERAL_NAME_num(names)
            for j in range(num_names):
                gen = lib.sk_GENERAL_NAME_value(names, j)
                if gen.type == lib.GEN_DNS:
                    data = gen.d.ia5
                    dns_data = lib.ASN1_STRING_get0_data(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    dns_len = lib.ASN1_STRING_length(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    if dns_data != ffi.NULL and dns_len > 0:
                        dns_name = ffi.buffer(dns_data, dns_len)[:].decode(
                            "ascii", errors="replace"
                        )
                        san_entries.append(("DNS", dns_name))
                elif gen.type == lib.GEN_EMAIL:
                    data = gen.d.ia5
                    email_data = lib.ASN1_STRING_get0_data(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    email_len = lib.ASN1_STRING_length(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    if email_data != ffi.NULL and email_len > 0:
                        email = ffi.buffer(email_data, email_len)[:].decode(
                            "ascii", errors="replace"
                        )
                        san_entries.append(("email", email))
                elif gen.type == lib.GEN_URI:
                    data = gen.d.ia5
                    uri_data = lib.ASN1_STRING_get0_data(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    uri_len = lib.ASN1_STRING_length(
                        ffi.cast("ASN1_STRING *", data)
                    )
                    if uri_data != ffi.NULL and uri_len > 0:
                        uri = ffi.buffer(uri_data, uri_len)[:].decode(
                            "ascii", errors="replace"
                        )
                        san_entries.append(("URI", uri))
        finally:
            lib.GENERAL_NAMES_free(names)
        break  # Only one SAN extension

    return tuple(san_entries)


class TLCPError(Exception):
    """Base exception for TLCP errors."""

    pass


class TLCPCertificateError(TLCPError):
    """Raised when there is a certificate-related error."""

    pass


class TLCPHandshakeError(TLCPError):
    """Raised when the TLCP handshake fails."""

    pass


class SSLContext:
    """
    An SSLContext for TLCP (GB/T 38636-2020) protocol.

    This context uses Tongsuo's NTLS implementation to provide TLCP support.
    TLCP uses SM2/SM3/SM4 cryptographic algorithms and supports double
    certificate mode (separate sign and encryption certificates).

    Usage::

        ctx = SSLContext()
        ctx.load_sign_certificate("sign.crt", "sign.key")
        ctx.load_enc_certificate("enc.crt", "enc.key")
        sock = ctx.wrap_socket(socket.socket(), server_hostname="example.com")
        sock.connect(("example.com", 443))
        sock.sendall(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        data = sock.recv(4096)
        sock.close()
    """

    def __init__(self, enable_ntls: bool = True):
        """
        Create a new TLCP SSLContext.

        Args:
            enable_ntls: Whether to enable NTLS mode (default True).
                         NTLS is required for TLCP protocol.
        """
        self._binding = Binding()
        self._lib = self._binding.lib
        self._ffi = self._binding.ffi

        if not getattr(self._lib, "Cryptography_HAS_NTLS", 0):
            raise TLCPError(
                "NTLS is not supported by the linked Tongsuo library. "
                "Please ensure you are using a Tongsuo build with NTLS support "
                "(compiled without OPENSSL_NO_NTLS)."
            )

        # Create SSL_CTX using NTLS method
        method = self._lib.NTLS_client_method()
        _openssl_assert(self._lib, method != self._ffi.NULL)

        self._ctx = self._lib.SSL_CTX_new(method)
        _openssl_assert(self._lib, self._ctx != self._ffi.NULL)

        if enable_ntls:
            self._lib.SSL_CTX_enable_ntls(self._ctx)

        # Default: don't verify peer cert (can be changed)
        self._verify_mode = False

        self._sign_cert: typing.Optional[str] = None
        self._sign_key: typing.Optional[str] = None
        self._enc_cert: typing.Optional[str] = None
        self._enc_key: typing.Optional[str] = None
        self._ca_file: typing.Optional[str] = None
        self._ca_path: typing.Optional[str] = None
        self._ciphers: typing.Optional[str] = None

    def __del__(self):
        if hasattr(self, "_ctx") and self._ctx is not None:
            self._lib.SSL_CTX_free(self._ctx)
            self._ctx = None

    @property
    def verify_mode(self) -> bool:
        """Whether to verify the server certificate."""
        return self._verify_mode

    @verify_mode.setter
    def verify_mode(self, value: bool):
        """Set whether to verify the server certificate."""
        self._verify_mode = value
        if value:
            self._lib.SSL_CTX_set_verify(
                self._ctx, self._lib.SSL_VERIFY_PEER, self._ffi.NULL
            )
        else:
            self._lib.SSL_CTX_set_verify(
                self._ctx, self._lib.SSL_VERIFY_NONE, self._ffi.NULL
            )

    def set_ciphers(self, cipherstring: str):
        """
        Set the available ciphers for TLCP connections.

        Common TLCP cipher suites:
        - ECC-SM2-SM4-CBC-SM3: Single certificate mode
        - ECC-SM2-WITH-SM4-SM3: Single certificate mode (alias)
        - ECDHE-SM2-SM4-CBC-SM3: Double certificate mode (ECDHE key exchange)
        - ECDHE-SM2-WITH-SM4-SM3: Double certificate mode (alias)

        Args:
            cipherstring: An OpenSSL cipher string.
        """
        cipherstring_bytes = cipherstring.encode("ascii")
        rc = self._lib.SSL_CTX_set_cipher_list(self._ctx, cipherstring_bytes)
        if rc == 0:
            raise TLCPError(
                f"Failed to set cipher list: {cipherstring}. "
                "No valid ciphers found."
            )
        self._ciphers = cipherstring

    def load_verify_locations(
        self,
        cafile: typing.Optional[str] = None,
        capath: typing.Optional[str] = None,
    ):
        """
        Load CA certificates for server certificate verification.

        Args:
            cafile: Path to a CA certificates file (PEM format).
            capath: Path to a directory containing CA certificates.
        """
        cafile_bytes = cafile.encode("utf-8") if cafile else self._ffi.NULL
        capath_bytes = capath.encode("utf-8") if capath else self._ffi.NULL

        rc = self._lib.SSL_CTX_load_verify_locations(
            self._ctx, cafile_bytes, capath_bytes
        )
        if rc != 1:
            raise TLCPError(
                f"Failed to load CA certificates from "
                f"cafile={cafile}, capath={capath}"
            )
        self._ca_file = cafile
        self._ca_path = capath

    def load_sign_certificate(
        self,
        certfile: str,
        keyfile: str,
        filetype: int = 1,  # SSL_FILETYPE_PEM
    ):
        """
        Load the signing certificate and private key for TLCP.

        In TLCP double certificate mode, the signing certificate is used
        for digital signature operations during the handshake.

        Args:
            certfile: Path to the signing certificate file (PEM format).
            keyfile: Path to the signing private key file (PEM format).
            filetype: Certificate file type. Default is PEM (1).
        """
        certfile_bytes = certfile.encode("utf-8")
        keyfile_bytes = keyfile.encode("utf-8")

        rc = self._lib.SSL_CTX_use_sign_certificate_file(
            self._ctx, certfile_bytes, filetype
        )
        if rc != 1:
            raise TLCPCertificateError(
                f"Failed to load sign certificate: {certfile}"
            )

        rc = self._lib.SSL_CTX_use_sign_PrivateKey_file(
            self._ctx, keyfile_bytes, filetype
        )
        if rc != 1:
            raise TLCPCertificateError(
                f"Failed to load sign private key: {keyfile}"
            )

        self._sign_cert = certfile
        self._sign_key = keyfile

    def load_enc_certificate(
        self,
        certfile: str,
        keyfile: str,
        filetype: int = 1,  # SSL_FILETYPE_PEM
    ):
        """
        Load the encryption certificate and private key for TLCP.

        In TLCP double certificate mode, the encryption certificate is used
        for key exchange operations during the handshake.

        Args:
            certfile: Path to the encryption certificate file (PEM format).
            keyfile: Path to the encryption private key file (PEM format).
            filetype: Certificate file type. Default is PEM (1).
        """
        certfile_bytes = certfile.encode("utf-8")
        keyfile_bytes = keyfile.encode("utf-8")

        rc = self._lib.SSL_CTX_use_enc_certificate_file(
            self._ctx, certfile_bytes, filetype
        )
        if rc != 1:
            raise TLCPCertificateError(
                f"Failed to load enc certificate: {certfile}"
            )

        rc = self._lib.SSL_CTX_use_enc_PrivateKey_file(
            self._ctx, keyfile_bytes, filetype
        )
        if rc != 1:
            raise TLCPCertificateError(
                f"Failed to load enc private key: {keyfile}"
            )

        self._enc_cert = certfile
        self._enc_key = keyfile

    def wrap_socket(
        self,
        sock: socket.socket,
        server_side: bool = False,
        server_hostname: typing.Optional[str] = None,
        suppress_ragged_eofs: bool = True,
        do_handshake_on_connect: bool = True,
    ) -> "TLCPSocket":
        """
        Wrap an existing socket with TLCP/NTLS encryption.

        This creates a TLCPSocket that performs the TLCP handshake and
        provides encrypted communication.

        Args:
            sock: The socket to wrap.
            server_side: Whether this is a server-side socket (default False).
            server_hostname: The expected server hostname (for SNI).
            suppress_ragged_eofs: Whether to suppress ragged EOF errors.
            do_handshake_on_connect: Whether to perform handshake immediately.

        Returns:
            A TLCPSocket wrapping the given socket with TLCP encryption.
        """
        return TLCPSocket(
            context=self,
            sock=sock,
            server_side=server_side,
            server_hostname=server_hostname,
            suppress_ragged_eofs=suppress_ragged_eofs,
            do_handshake_on_connect=do_handshake_on_connect,
        )


class TLCPSocket:
    """
    A socket wrapped with TLCP/NTLS encryption.

    This class provides a socket-like interface for TLCP connections.
    It wraps a regular socket and adds TLCP encryption via Tongsuo.
    """

    def __init__(
        self,
        context: SSLContext,
        sock: socket.socket,
        server_side: bool = False,
        server_hostname: typing.Optional[str] = None,
        suppress_ragged_eofs: bool = True,
        do_handshake_on_connect: bool = True,
    ):
        self._context = context
        self._sock = sock
        self._server_side = server_side
        self._server_hostname = server_hostname
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._lib = context._lib
        self._ffi = context._ffi
        self._ssl = None
        self._rbio = None
        self._wbio = None
        self._connected = False
        self._closed = False

        # Create SSL object
        self._ssl = self._lib.SSL_new(context._ctx)
        _openssl_assert(self._lib, self._ssl != self._ffi.NULL)

        # Enable NTLS on the SSL object as well
        self._lib.SSL_enable_ntls(self._ssl)

        # Set up BIOs connected to the socket fd
        fd = sock.fileno()
        rc = self._lib.SSL_set_fd(self._ssl, fd)
        _openssl_assert(self._lib, rc == 1)

        # Set connect or accept state
        if server_side:
            self._lib.SSL_set_accept_state(self._ssl)
        else:
            self._lib.SSL_set_connect_state(self._ssl)

        # Set SNI hostname if provided (not typically used in NTLS, but
        # some servers may support it)
        if server_hostname and not server_side:
            hostname_bytes = server_hostname.encode("ascii")
            self._lib.SSL_set_tlsext_host_name(self._ssl, hostname_bytes)

        # Set verify mode
        if not context.verify_mode:
            self._lib.SSL_set_verify(
                self._ssl, self._lib.SSL_VERIFY_NONE, self._ffi.NULL
            )

        # Save socket timeout and make it blocking for handshake
        self._orig_timeout = sock.gettimeout()

        if do_handshake_on_connect and sock.getpeername():
            self.do_handshake()

    def __del__(self):
        self.close()

    def do_handshake(self):
        """Perform the TLCP/NTLS handshake."""
        if self._ssl is None:
            raise TLCPError("SSL object has been freed")

        # SSL_do_handshake needs a blocking socket. If the socket has a
        # timeout, temporarily make it fully blocking for the handshake.
        orig_timeout = self._sock.gettimeout()
        if orig_timeout is not None and orig_timeout != 0:
            self._sock.setblocking(True)

        try:
            rc = self._lib.SSL_do_handshake(self._ssl)
            if rc <= 0:
                err = self._lib.SSL_get_error(self._ssl, rc)
                err_reason = _get_ssl_error_string(self._lib, self._ffi)
                raise TLCPHandshakeError(
                    f"TLCP handshake failed with error code {err}: "
                    f"{err_reason}"
                )
            self._connected = True
        finally:
            # Restore original timeout
            if orig_timeout is not None and orig_timeout != 0:
                self._sock.settimeout(orig_timeout)

    def send(self, data: bytes) -> int:
        """
        Send data over the TLCP connection.

        Args:
            data: The data to send.

        Returns:
            The number of bytes sent.

        Raises:
            ssl.SSLWantReadError: If the operation would block waiting for read.
            ssl.SSLWantWriteError: If the operation would block waiting for write.
            TLCPError: On other SSL errors.
        """
        if self._ssl is None:
            raise TLCPError("Connection is closed")

        buf = self._ffi.from_buffer(data)
        rc = self._lib.SSL_write(self._ssl, buf, len(data))
        if rc <= 0:
            err = self._lib.SSL_get_error(self._ssl, rc)
            if err == self._lib.SSL_ERROR_WANT_READ:
                raise _stdlib_ssl.SSLWantReadError()
            if err == self._lib.SSL_ERROR_WANT_WRITE:
                raise _stdlib_ssl.SSLWantWriteError()
            err_reason = _get_ssl_error_string(self._lib, self._ffi)
            raise TLCPError(f"SSL_write failed with error {err}: {err_reason}")
        return rc

    def sendall(self, data: bytes):
        """
        Send all data over the TLCP connection.

        Args:
            data: The data to send.
        """
        total_sent = 0
        while total_sent < len(data):
            sent = self.send(data[total_sent:])
            total_sent += sent

    def recv(self, bufsize: int = 4096) -> bytes:
        """
        Receive data from the TLCP connection.

        Args:
            bufsize: Maximum number of bytes to receive.

        Returns:
            The received data as bytes.

        Raises:
            ssl.SSLWantReadError: If the operation would block waiting for read.
            ssl.SSLWantWriteError: If the operation would block waiting for write.
            TLCPError: On other SSL errors.
        """
        if self._ssl is None:
            raise TLCPError("Connection is closed")

        buf = self._ffi.new(f"char[{bufsize}]")
        rc = self._lib.SSL_read(self._ssl, buf, bufsize)
        if rc <= 0:
            err = self._lib.SSL_get_error(self._ssl, rc)
            if err == self._lib.SSL_ERROR_ZERO_RETURN:
                return b""
            if err == self._lib.SSL_ERROR_WANT_READ:
                raise _stdlib_ssl.SSLWantReadError()
            if err == self._lib.SSL_ERROR_WANT_WRITE:
                raise _stdlib_ssl.SSLWantWriteError()
            if (
                self._suppress_ragged_eofs
                and err == self._lib.SSL_ERROR_SYSCALL
            ):
                return b""
            err_reason = _get_ssl_error_string(self._lib, self._ffi)
            raise TLCPError(f"SSL_read failed with error {err}: {err_reason}")
        return self._ffi.buffer(buf, rc)[:]

    def recv_into(self, buffer, nbytes: typing.Optional[int] = None) -> int:
        """
        Receive data from the TLCP connection into a buffer.

        Args:
            buffer: A writable buffer object.
            nbytes: Maximum number of bytes to receive.

        Returns:
            The number of bytes received.
        """
        if nbytes is None:
            nbytes = len(buffer)

        data = self.recv(nbytes)
        buffer[: len(data)] = data
        return len(data)

    def shutdown(self):
        """Perform an orderly SSL shutdown."""
        if self._ssl is not None:
            self._lib.SSL_shutdown(self._ssl)

    def close(self):
        """Close the TLCP connection and free resources."""
        if self._closed:
            return
        self._closed = True

        if self._ssl is not None:
            self._lib.SSL_shutdown(self._ssl)
            self._lib.SSL_free(self._ssl)
            self._ssl = None

    def getpeername(self):
        """Return the remote address of the underlying socket."""
        return self._sock.getpeername()

    def fileno(self) -> int:
        """Return the file descriptor of the underlying socket."""
        return self._sock.fileno()

    def settimeout(self, timeout: typing.Optional[float]):
        """Set a timeout on the underlying socket."""
        self._sock.settimeout(timeout)

    def gettimeout(self) -> typing.Optional[float]:
        """Return the timeout of the underlying socket."""
        return self._sock.gettimeout()

    def setblocking(self, flag: bool):
        """Set blocking or non-blocking mode on the underlying socket."""
        self._sock.setblocking(flag)

    def makefile(self, mode="r", buffering=None, **kwargs):
        """Return a file object associated with this socket (unsupported)."""
        raise NotImplementedError("makefile() is not supported on TLCPSocket")

    def pending(self) -> int:
        """Return the number of bytes pending in the SSL buffer."""
        if self._ssl is None:
            return 0
        return self._lib.SSL_pending(self._ssl)

    def getpeercert(self, binary_form: bool = False):
        """
        Return the peer certificate.

        If *binary_form* is True, return the DER-encoded certificate bytes.
        If *binary_form* is False (default), return a dict with parsed
        certificate fields compatible with ``ssl.match_hostname()``.

        Returns None if no peer certificate is available.
        """
        if self._ssl is None:
            return None

        x509 = self._lib.SSL_get_peer_certificate(self._ssl)
        if x509 == self._ffi.NULL:
            return None

        try:
            if binary_form:
                # Write DER form via a memory BIO
                bio = self._lib.BIO_new(self._lib.BIO_s_mem())
                if bio == self._ffi.NULL:
                    return None
                try:
                    rc = self._lib.i2d_X509_bio(bio, x509)
                    if rc != 1:
                        return None
                    length = self._lib.BIO_ctrl_pending(bio)
                    buf = self._ffi.new(f"char[{length}]")
                    n = self._lib.BIO_read(bio, buf, length)
                    if n <= 0:
                        return None
                    return self._ffi.buffer(buf, n)[:]
                finally:
                    self._lib.BIO_free(bio)

            # Parse certificate into dict for ssl.match_hostname()
            result = {}

            # Subject
            subject_name = self._lib.X509_get_subject_name(x509)
            if subject_name != self._ffi.NULL:
                result["subject"] = _parse_x509_name(
                    self._lib, self._ffi, subject_name
                )

            # Issuer
            issuer_name = self._lib.X509_get_issuer_name(x509)
            if issuer_name != self._ffi.NULL:
                result["issuer"] = _parse_x509_name(
                    self._lib, self._ffi, issuer_name
                )

            # Subject Alternative Name
            san = _parse_subject_alt_name(self._lib, self._ffi, x509)
            if san:
                result["subjectAltName"] = san

            # Serial number
            serial_asn1 = self._lib.X509_get_serialNumber(x509)
            if serial_asn1 != self._ffi.NULL:
                bn = self._lib.ASN1_INTEGER_to_BN(serial_asn1, self._ffi.NULL)
                if bn != self._ffi.NULL:
                    try:
                        hex_ptr = self._lib.BN_bn2hex(bn)
                        if hex_ptr != self._ffi.NULL:
                            try:
                                result["serialNumber"] = self._ffi.string(
                                    hex_ptr
                                ).decode("ascii")
                            finally:
                                self._lib.OPENSSL_free(hex_ptr)
                    finally:
                        self._lib.BN_free(bn)

            # notBefore / notAfter
            not_before = self._lib.X509_getm_notBefore(x509)
            if not_before != self._ffi.NULL:
                data = self._lib.ASN1_STRING_get0_data(
                    self._ffi.cast("ASN1_STRING *", not_before)
                )
                slen = self._lib.ASN1_STRING_length(
                    self._ffi.cast("ASN1_STRING *", not_before)
                )
                if data != self._ffi.NULL and slen > 0:
                    result["notBefore"] = self._ffi.buffer(data, slen)[
                        :
                    ].decode("ascii")

            not_after = self._lib.X509_getm_notAfter(x509)
            if not_after != self._ffi.NULL:
                data = self._lib.ASN1_STRING_get0_data(
                    self._ffi.cast("ASN1_STRING *", not_after)
                )
                slen = self._lib.ASN1_STRING_length(
                    self._ffi.cast("ASN1_STRING *", not_after)
                )
                if data != self._ffi.NULL and slen > 0:
                    result["notAfter"] = self._ffi.buffer(data, slen)[
                        :
                    ].decode("ascii")

            return result
        finally:
            self._lib.X509_free(x509)

    def write(self, data: bytes) -> int:
        """Alias for send(), for file-like object compatibility."""
        return self.send(data)

    def read(self, bufsize: int = 4096, buffer=None) -> bytes:
        """Alias for recv(), for file-like object compatibility."""
        data = self.recv(bufsize)
        if buffer is not None:
            buffer[: len(data)] = data
            return len(data)  # type: ignore[return-value]
        return data

    def get_version(self) -> str:
        """
        Return the protocol version of the connection.

        Returns:
            A string describing the protocol version (e.g., 'NTLSv1.1').
        """
        if self._ssl is None:
            return ""
        version = self._lib.SSL_get_version(self._ssl)
        return self._ffi.string(version).decode("ascii")

    def get_cipher(self) -> typing.Optional[str]:
        """
        Return the name of the cipher currently in use.

        Returns:
            The cipher name, or None if not connected.
        """
        if self._ssl is None:
            return None
        cipher = self._lib.SSL_get_current_cipher(self._ssl)
        if cipher == self._ffi.NULL:
            return None
        name = self._lib.SSL_CIPHER_get_name(cipher)
        return self._ffi.string(name).decode("ascii")

    def connect(self, address: tuple):
        """
        Connect to address and perform the TLCP handshake.

        Args:
            address: A (host, port) tuple.
        """
        self._sock.connect(address)
        # Re-set the fd after connect
        rc = self._lib.SSL_set_fd(self._ssl, self._sock.fileno())
        _openssl_assert(self._lib, rc == 1)
        self.do_handshake()

    @property
    def context(self) -> SSLContext:
        """Return the SSLContext associated with this socket."""
        return self._context

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


def _get_ssl_error_string(lib, ffi) -> str:
    """Get the last SSL error string from the error queue."""
    errors = []
    while True:
        err = lib.ERR_get_error()
        if err == 0:
            break
        buf = ffi.new("char[256]")
        lib.ERR_error_string_n(err, buf, 256)
        errors.append(ffi.string(buf).decode("ascii", errors="replace"))
    return "; ".join(errors) if errors else "unknown error"


def create_default_context(
    verify: bool = False,
    cafile: typing.Optional[str] = None,
    capath: typing.Optional[str] = None,
    ciphers: typing.Optional[str] = None,
) -> SSLContext:
    """
    Create an SSLContext with default settings for TLCP client connections.

    Args:
        verify: Whether to verify server certificates (default False).
        cafile: Path to CA certificates file for verification.
        capath: Path to CA certificates directory for verification.
        ciphers: Cipher string. Default is "ECC-SM2-SM4-CBC-SM3".

    Returns:
        A configured SSLContext.
    """
    ctx = SSLContext()
    ctx.verify_mode = verify

    if cafile or capath:
        ctx.load_verify_locations(cafile=cafile, capath=capath)

    if ciphers:
        ctx.set_ciphers(ciphers)
    else:
        ctx.set_ciphers("ECC-SM2-SM4-CBC-SM3")

    return ctx
