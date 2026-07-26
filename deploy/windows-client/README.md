# Windows client deploy

Use this on the second user's Windows PC.

## GitHub Actions

The recommended path is to build the Windows client on GitHub:

1. Open the repository on GitHub.
2. Go to `Actions`.
3. Select `Build Windows Client`.
4. Press `Run workflow`.
5. Download the `messenger-windows` artifact.

The artifact contains `messenger.exe` and the Qt/OpenSSL runtime files needed to run it.

## Requirements

- Qt 6 for MSVC 64-bit.
- Visual Studio Build Tools with the MSVC compiler.
- OpenSSL for Windows.
- `libsignal-protocol-c` built for the same compiler and architecture.

Default paths used by `build.bat`:

- Qt: `C:\Qt\6.7.2\msvc2019_64`
- Signal: `C:\libs\signal-protocol-c`
- OpenSSL: `C:\libs\OpenSSL-Win64`

You can override them:

```bat
set QT_DIR=C:\Qt\6.7.2\msvc2019_64
set SIGNAL_DIR=C:\libs\signal-protocol-c
set OPENSSL_DIR=C:\libs\OpenSSL-Win64
deploy\windows-client\build.bat
```

In the login window, enter the Ubuntu server IP or DNS name and port `5555`.

Note: Windows secure local-key storage still needs a DPAPI/Credential Manager backend. Until that is added, Windows builds should be treated as test builds, not high-security builds.
