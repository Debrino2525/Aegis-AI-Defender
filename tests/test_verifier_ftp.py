"""Live retest must not clear a port-21 CVE because anonymous FTP is disabled."""

import asyncio

from aegis.core.verifier import FindingVerifier


async def _start_ftp(reject_anonymous: bool):
    """Minimal FTP listener. Banner advertises vulnerable ProFTPD 1.3.5."""

    async def handle(reader, writer):
        writer.write(b"220 ProFTPD 1.3.5 Server ready.\r\n")
        await writer.drain()
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                if not line:
                    break
                cmd = line.decode("latin1", errors="replace").strip().upper()
                if cmd.startswith("USER"):
                    if reject_anonymous:
                        writer.write(b"530 Login incorrect.\r\n")
                    else:
                        writer.write(b"230 User logged in.\r\n")
                elif cmd.startswith("PASS"):
                    writer.write(b"530 Login incorrect.\r\n")
                elif cmd.startswith("QUIT"):
                    writer.write(b"221 Bye.\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 Unknown command.\r\n")
                await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


async def test_proftpd_cve_stays_open_when_anonymous_login_is_refused():
    """CVE-2015-3306 is unauthenticated mod_copy. Refusing USER anonymous does not patch it."""
    server, port = await _start_ftp(reject_anonymous=True)
    async with server:
        verifier = FindingVerifier()
        result = await verifier.verify_finding(
            "CVE-2015-3306",
            "ProFTPD mod_copy Command Execution",
            "127.0.0.1",
            port,
        )
        assert result["status"] != "REMEDIATED", result
        assert result["is_vulnerable"] is True, result

        instructions = verifier.get_instructions(
            "CVE-2015-3306",
            "ProFTPD mod_copy Command Execution",
            "127.0.0.1",
            port,
        )
        assert instructions["method"] != "FTP Anonymous Authentication Audit (RFC 959)", instructions
        assert "530" not in instructions["expected_remediated"]

        vsftpd = await verifier.verify_finding(
            "CVE-2011-2523",
            "vsftpd 2.3.4 Backdoor",
            "127.0.0.1",
            port,
        )
        assert vsftpd["status"] != "REMEDIATED", vsftpd
        assert vsftpd["is_vulnerable"] is True, vsftpd
    print("[+] test_proftpd_cve_stays_open_when_anonymous_login_is_refused: PASSED")


async def test_anonymous_ftp_finding_still_uses_login_probe():
    server, port = await _start_ftp(reject_anonymous=True)
    async with server:
        verifier = FindingVerifier()
        refused = await verifier.verify_finding(
            "AEGIS-TMPL-004",
            "Anonymous FTP Login Allowed",
            "127.0.0.1",
            port,
        )
        assert refused["status"] == "REMEDIATED", refused
        assert refused["is_vulnerable"] is False

        instructions = verifier.get_instructions(
            "AEGIS-TMPL-004",
            "Anonymous FTP Login Allowed",
            "127.0.0.1",
            port,
        )
        assert instructions["method"] == "FTP Anonymous Authentication Audit (RFC 959)"
    print("[+] test_anonymous_ftp_finding_still_uses_login_probe: PASSED")


async def test_anonymous_ftp_login_accepted_stays_vulnerable():
    server, port = await _start_ftp(reject_anonymous=False)
    async with server:
        verifier = FindingVerifier()
        accepted = await verifier.verify_finding(
            "AEGIS-TMPL-004",
            "Anonymous FTP Login Allowed",
            "127.0.0.1",
            port,
        )
        assert accepted["status"] == "VULNERABLE", accepted
        assert accepted["is_vulnerable"] is True
    print("[+] test_anonymous_ftp_login_accepted_stays_vulnerable: PASSED")


def main():
    asyncio.run(test_proftpd_cve_stays_open_when_anonymous_login_is_refused())
    asyncio.run(test_anonymous_ftp_finding_still_uses_login_probe())
    asyncio.run(test_anonymous_ftp_login_accepted_stays_vulnerable())
    print("\n[=== VERIFIER FTP ROUTING TESTS PASSED ===]")


if __name__ == "__main__":
    main()
