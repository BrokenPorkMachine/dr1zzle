"""goat -- the dr1zzle private loader (host side).

Modules:
    der        DER encode/decode, matching src/goat/asn1.c
    aes        AES-256-CBC, matching src/goat/aes.c
    rsa        RSA keygen/sign/verify plus the self-signed certificate
    container  the GOAT container: seal, parse, verify, decrypt
    usb        libusb transport and the pwndfu DFU command channel
    kload      plan a dr1zzle image and boot it on a pwndfu device
    pwn        the one thing delegated: running checkm8 via the vendored ipwndfu
    cli        the `goat` command line
"""

__version__ = "1"
