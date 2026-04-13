"""Shared certificate utilities for VPN plugins."""

from __future__ import annotations

import subprocess

from tv.app_config import cfg

_SHA256_EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def generate_cert_sha256(host: str, port: str) -> str:
    """Generate SHA256 cert fingerprint via openssl pipe chain.

    Returns lowercase hex string (e.g. "aabb11...") or empty string on failure.
    """
    procs: list[subprocess.Popen] = []
    try:
        s_client = subprocess.Popen(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(s_client)
        x509 = subprocess.Popen(
            ["openssl", "x509", "-outform", "DER"],
            stdin=s_client.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        procs.append(x509)
        s_client.stdout.close()

        s_client.stdin.write(b"\n")
        s_client.stdin.close()

        der_out, x509_err = x509.communicate(timeout=cfg.timeouts.cert_generation)
        s_client.wait(timeout=cfg.timeouts.cert_openssl)

        if not der_out:
            return ""

        dgst = subprocess.Popen(
            ["openssl", "dgst", "-sha256"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(dgst)
        out, _ = dgst.communicate(input=der_out, timeout=cfg.timeouts.cert_openssl)

        if dgst.returncode == 0 and out:
            text = out.decode().strip()
            if "= " in text:
                cert = text.split("= ", 1)[1].strip()
            else:
                cert = text
            if cert == _SHA256_EMPTY:
                return ""
            return cert
    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                pass
    return ""


def generate_spki_pin(host: str, port: str) -> str:
    """Generate SPKI pin-sha256 for openconnect --servercert.

    Returns 'pin-sha256:BASE64' string or empty string on failure.
    openconnect uses SPKI hash (Subject Public Key Info), not cert DER hash.
    """
    import base64

    procs: list[subprocess.Popen] = []
    try:
        s_client = subprocess.Popen(
            ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(s_client)
        pubkey = subprocess.Popen(
            ["openssl", "x509", "-pubkey", "-noout"],
            stdin=s_client.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(pubkey)
        s_client.stdout.close()
        s_client.stdin.write(b"\n")
        s_client.stdin.close()

        pem_out, _ = pubkey.communicate(timeout=cfg.timeouts.cert_generation)
        s_client.wait(timeout=cfg.timeouts.cert_openssl)
        if not pem_out:
            return ""

        der_conv = subprocess.Popen(
            ["openssl", "pkey", "-pubin", "-outform", "DER"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(der_conv)
        der_out, _ = der_conv.communicate(
            input=pem_out, timeout=cfg.timeouts.cert_openssl
        )
        if not der_out:
            return ""

        dgst = subprocess.Popen(
            ["openssl", "dgst", "-sha256", "-binary"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        procs.append(dgst)
        hash_out, _ = dgst.communicate(input=der_out, timeout=cfg.timeouts.cert_openssl)
        if not hash_out:
            return ""

        return f"pin-sha256:{base64.b64encode(hash_out).decode()}"
    except (subprocess.TimeoutExpired, OSError):
        pass
    finally:
        for p in procs:
            try:
                p.kill()
            except OSError:
                pass
        for p in procs:
            try:
                p.wait(timeout=2)
            except Exception:
                pass
    return ""
