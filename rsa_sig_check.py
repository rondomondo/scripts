#!/usr/bin/env python

import argparse
import sys
import os
from datetime import datetime
from os import path
import pprint
from urllib3 import connection

from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import PKCS1_v1_5


from Crypto import Random
from Crypto.Util.asn1 import DerSequence
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.PublicKey import RSA
from binascii import a2b_base64
from base64 import urlsafe_b64decode, urlsafe_b64encode
from OpenSSL import crypto


debug = False


def p(m):
    if debug:
        print(m)


def md(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)


def maybe_pad(s):
    return (s + '=' * (4 - len(s) % 4))


def generate_rsa_key_pair(name='certificate', bits=2048, key_dir="keys/"):
    md(key_dir)
    random_generator = Random.new().read
    key = RSA.generate(bits, random_generator)
    privateKey = key.exportKey()
    publicKey = key.publickey().exportKey()
    with open("%s%s%s" % (key_dir, name, ".pem"), "wt") as outfile:
        outfile.write(privateKey)
    with open("%s%s%s" % (key_dir, name, ".key.pub"), "wt") as outfile:
        outfile.write(publicKey)


u""" Create a self signed X509 certificate and save it and related
    artifacts to cert_dir """


def use_or_create_cert(*args, **kwargs):
    name = kwargs.get("cert_name", 'certificate.crt')
    cert_dir = kwargs.get("cert_dir", 'keys/' if name == 'certificate.crt'
                          else "certsext/")
    bits = kwargs.get("bits", 2048)

    md(cert_dir)

    new_cert_as_pem = None
    CERT_FILE = "%s%s" % (cert_dir, name)
    KEY_FILE = "%s%s%s" % (cert_dir, ".".join(name.split(".")[:-1]), ".pem")
    PUBLIC_KEY_FILE = "%s%s%s" % (cert_dir, ".".join(name.split(".")[:-1]),
                                  ".key.pub")
    try:
        if not path.exists(CERT_FILE) and not path.exists(KEY_FILE):
            p("Creating self signed certificate and key pair, details \
    as follows\ncertificate name:  \
    %s\ncert private key:  %s\ncert public  key:  %s" % (CERT_FILE, KEY_FILE,
                                                         PUBLIC_KEY_FILE))
            u""" create a key pair of 'bits' length """
            key_pair = crypto.PKey()
            key_pair.generate_key(crypto.TYPE_RSA, bits)

            u""" create a self-signed cert """
            new_cert = crypto.X509()
            new_cert.set_version(1)
            new_cert.set_serial_number(1000)
            new_cert.get_subject().C = "AU"
            new_cert.get_subject().ST = "NSW"
            new_cert.get_subject().L = "Sydney"
            new_cert.get_subject().O = "Widgets from XXX.COM.AU"
            new_cert.get_subject().OU = "Sales"
            new_cert.get_subject().CN = "xxx.com.au"
            new_cert.set_notBefore(b'' + datetime.now().strftime("%Y%m%d%H%M%SZ"))
            u""" valid for 1 week """
            new_cert.gmtime_adj_notAfter(1*7*24*60*60)

            u""" the issuer is me/us """
            new_cert.set_issuer(new_cert.get_subject())
            new_cert.set_pubkey(key_pair)
            u""" self sign our new_cert using SHA256 hash algorithm """
            new_cert.sign(key_pair, 'SHA256')

            new_cert_as_pem = crypto.dump_certificate(crypto.FILETYPE_PEM,
                                                      new_cert)

            open(CERT_FILE, "wt").write(new_cert_as_pem)
            privateKeyPEM = crypto.dump_privatekey(
                                        crypto.FILETYPE_PEM, key_pair)
            open(KEY_FILE, "wt").write(privateKeyPEM)

            p("Created  self signed certificate and key pair")
            kwargs['cert_format'] = None
            pem, publicKey = save_publickey_from_pem_cert(args, **kwargs)
            return pem, publicKey, privateKeyPEM

        elif path.exists(CERT_FILE) and not path.exists(KEY_FILE):
            p("Use a certificate to verify")
            return get_publickey_from_cert(args, **kwargs), None

        elif path.exists(CERT_FILE) and path.exists(KEY_FILE):
            with open(KEY_FILE) as infile:
                p("Using existing certificate details as follows\ncertificate name: \
    %s\ncertificate key:  %s" % (CERT_FILE, KEY_FILE))
                privateKeyPEM = infile.read()

                return get_publickey_from_cert(args, **kwargs), privateKeyPEM
        elif not path.exists(CERT_FILE) and path.exists(KEY_FILE):
            with open(KEY_FILE) as infile:
                p("Using existing private key")
                privateKeyPEM = infile.read()

                return None, None, privateKeyPEM
        else:
            p("some big error")
            sys.exit(1)

    except Exception as e:
        print("Some error with certificate and/or key: %s Exception: %s"
              % (name, e))
        sys.exit(1)


def get_publickey_from_cert(*args, **kwargs):
    name = kwargs.get('cert_name', 'certificate.crt')
    cert_dir = kwargs.get("cert_dir", 'keys/' if name == 'certificate.crt'
                          else "certsext/")
    cert_format = kwargs.get("cert_format", 'DER'
                             if name != 'certificate.crt' else None)
    filename = "%s%s" % (cert_dir, name)
    u""" default to expecting the cert to be in PEM format """
    if not cert_format:
        cert_in_pem_format = open(filename).read()
        p("Certificate (%s) in PEM format\n%s\n" % (filename,
                                                    cert_in_pem_format))
        lines = cert_in_pem_format.replace(" ", "").split()
        der = a2b_base64(''.join(lines[1:-1]))

    elif cert_format.lower() == 'der':
        der = open(filename).read()
    else:
        print("Unsupported certificate (%s) format: %s" % (name, cert_format))
        sys.exit(1)

        u""" Read the publicKey part of the cert """
    try:
        cert = DerSequence()
        cert.decode(der)
    except Exception as e:
        print ("DerSequence exception %s %s" % (name, e))
    u""" see http://bit.ly/x509_terms for what the terms mean etc """

    tbsCertificate = DerSequence()
    tbsCertificate.decode(cert[0])

    u""" subjectPublicKeyInfo is going to be a bytestring here btw, so many
    non-printable characters.

    base64.b64encode(subjectPublicKeyInfo) it, if you want to look at it
    """
#     for i,t in enumerate(tbsCertificate):
#         pprint.pprint(t)
    subjectPublicKeyInfo = tbsCertificate[6]

    u""" create a publicKey object and return the key object and PEM format
    for good measure """
    publicKey = RSA.importKey(subjectPublicKeyInfo)
    return publicKey.publickey().exportKey(), publicKey.publickey()


def save_publickey_from_pem_cert(*args, **kwargs):
    name = kwargs.get('cert_name', 'certificate.crt')
    cert_dir = kwargs.get("cert_dir", 'keys/')
    pem, publicKey = get_publickey_from_cert(args, **kwargs)

    with open("%s%s%s" % (cert_dir, ".".join(name.split(".")[:-1]),
                          ".key.pub"), "wt") as outfile:
        outfile.write(pem)
    return pem, publicKey



u"""
    keydata = ['n', 'e', 'd', 'p', 'q', 'u']
    
    keydata
    Dictionary of RSA parameters.
    
    A public key will only have the following entries:
    
    n, the modulus.
    e, the public exponent.
    A private key will also have:
    
    d, the private exponent.
    p, the first factor of n.
    q, the second factor of n.
    u, the CRT coefficient (1/p) mod q.


TBSCertificate  ::=  SEQUENCE  {
        version         [0]  EXPLICIT Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                             -- If present, version MUST be v2 or v3
        extensions      [3]  EXPLICIT Extensions OPTIONAL
                             -- If present, version MUST be v3
        }

        http://docs.ganeti.org/ganeti/2.8/html/design-x509-ca.html

"""


def sign_data(*args, **kwargs):
    componants = use_or_create_cert(args, **kwargs)

    privateKeyPEM = componants[-1]
    privateKey = RSA.importKey(privateKeyPEM)

    data = kwargs.get("data", args[0])
    use_pkcs1_v1_5 = kwargs.get("use_pkcs1_v1_5", False)

    if use_pkcs1_v1_5:
        hash_object = SHA512.new(data)
        signer = PKCS1_v1_5.new(privateKey)
        signature = signer.sign(hash_object)
        signature_bytes = signature
        print("Data was signed using PKCS1_v1_5 from Crypto.Signature. The signature is\n%s\n" % urlsafe_b64encode(signature_bytes))
        print("\nTo verify with PKCS1_v1_5 from Crypto.Signature execute\n")
        cmd = "/usr/bin/env python %s --debug --data \"%s\" --verify --signature \"%s\" " % (sys.argv[0],data, urlsafe_b64encode(signature_bytes))
        if kwargs.get('cert_name',None):
            cmd += " --cert-name %s " % kwargs.get('cert_name')

        if kwargs.get('cert_dir',None):
            cmd += " --cert-dir %s " % kwargs.get('cert_dir')
        print(cmd)
    else:
        hash_of_data = SHA256.new(data).hexdigest()
        signature = privateKey.sign(hash_of_data, "")
        signature_bytes = long_to_bytes(signature[0])
        print("Data was signed using the private key of the issuer. The signature is\n%s\n" % urlsafe_b64encode(signature_bytes))
        print("\nTo verify with the signers public key execute\n")
        cmd = "/usr/bin/env python %s --debug --data \"%s\" --verify --signature \"%s\" " % (sys.argv[0],data, urlsafe_b64encode(signature_bytes))

        if kwargs.get('cert_name',None):
            cmd += " --cert-name %s " % kwargs.get('cert_name')

        if kwargs.get('cert_dir',None):
            cmd += " --cert-dir %s " % kwargs.get('cert_dir')
        print(cmd)
    return signature


def verify_data(*args, **kwargs):
    name = kwargs.get('cert_name', 'certificate.crt')
    kwargs["cert_format"] = 'DER' if name != 'certificate.crt' else None
    componants = get_publickey_from_cert(args, **kwargs)
    data = kwargs.get("data", args[0])
    signature = kwargs.get("signature", None)
    use_pkcs1_v1_5 = kwargs.get("use_pkcs1_v1_5", False)
    publicKey = componants[1]
    if use_pkcs1_v1_5:
        hash_object = SHA512.new(data)
        verifier = PKCS1_v1_5.new(publicKey)
        verified = verifier.verify(hash_object, signature)
        print("\nverification was %s with PKCS1_v1_5 from Crypto.Signature\n"
              % ("successful" if verified else "unsuccessful"))
    else:
        hash_of_data = SHA256.new(data).hexdigest()
        verified = publicKey.verify(hash_of_data, (signature,))
        print("\nverification was %s with RSA public key of signer\n"
              % ("successful" if verified else "unsuccessful"))

    return verified


u""" Some random bits and pieces I found on my travels

# http://www.laurentluce.com/posts/python-and-cryptography-with-pycrypto/

# http://info.ssl.com/article.aspx?id=12149
# https://www.sslshopper.com/article-most-common-openssl-commands.html

# Check a Certificate Signing Request (CSR)
openssl req -text -noout -verify -in CSR.csr
# Check a private key
openssl rsa -in privateKey.key -check
# Check a certificate
openssl x509 -in certificate.crt -text -noout
# Check a PKCS#12 file (.pfx or .p12)
openssl pkcs12 -info -in keyStore.p12


# https://warrenguy.me/blog/regenerating-rsa-private-key-python

# Generate an SSL CSR for me
openssl x509 -req -sha256 -days 365 -in domain.com.csr -signkey certificate.pem
    -out certificate.crt

#Check an MD5 hash of the public key to ensure that it matches with what is in
#a CSR or private key

openssl x509 -noout -modulus -in certificate.crt | openssl md5
openssl rsa -noout -modulus -in privateKey.key | openssl md5
openssl req -noout -modulus -in CSR.csr | openssl md5

#Check an SSL connection. All the certificates (including Intermediates)
#should be displayed
openssl s_client -connect google.com:443

#Convert a DER file (.crt .cer .der) to PEM
openssl x509 -inform der -in certificate.cer -out certificate.pem

#Convert a PEM file to DER
openssl x509 -outform der -in certificate.pem -out certificate.der

#Convert a PKCS#12 file (.pfx .p12) containing a private key and certificates
#to PEM
openssl pkcs12 -in keyStore.pfx -out keyStore.pem -nodes


"""


u""" grab a sites ssl cert and save locally in DER format """


def get_cert_from_url(*args, **kwargs):
    try:
        host = args[0]
        external_certs_dir =  kwargs.get("cert_dir", "certsext/")
        port = kwargs.get("port", 443)
       
        md(external_certs_dir)
        HTTPSConnection = connection.VerifiedHTTPSConnection(host,port=port)#,timeout=30)
        HTTPSConnection.connect()
        der = HTTPSConnection.sock.getpeercert(binary_form=True)
        cert_file = "%s/%s%s" % (external_certs_dir, host, ".crt")
        KEY_FILE = "%s/%s%s" % (external_certs_dir, host, ".pem")
        with open(KEY_FILE, "wb") as outfile:
            outfile.write("THIS SHOULD CONTAIN A PRIVATE KEY IN PEM FORMAT")
            print("Saved dummy key from https://%s to %s\n" % (host, KEY_FILE))
            print("If you have access to the actual real issuers privateKey,\n\
and you might want to do some signing, then copy the real\nkey to %s" % (KEY_FILE))
        with open(cert_file, "wb") as outfile:
            outfile.write(der)
            print("Saved external certificate from https://%s to %s" %
                  (host, cert_file))
        kwargs['cert_name'] = "%s%s" % (host, ".crt")
        kwargs['cert_dir'] = external_certs_dir
        kwargs["cert_format"] = "der"
        save_publickey_from_pem_cert(*args, **kwargs)
    except Exception as e:
        print("%s" % (e))
        pass



u"""
Here are some common things you may want to do...

1)  Download a SSL cert from some website so you can maybe extract the
    RSA public key from it easily. You may want to use this public key
    to verify a signature for example

    #python rsa-sig-check.py  --url website.com

    #output looks something like this
    Saved dummy key from https://website.com to certsext/website.com.pem
    If you have access to the actual real issuers privateKey,
    and you might want to do some signing, then copy the real
    key to certsext/website.com.pem
    Saved external certificate from https://website.com to certsext/website.com.crt


2)  Digitally sign some data or message with a private key. I've shown two
    approaches. The first being a simple RSA key sign with private key, and
    the other using the more specialised PKCS1_v1_5. This one is useful to
    know if you may need to verify some JWT RSA signed tokens, like from AWS.
    #python rsa-sig-check.py   --data "Some message to sign" --sign --cert-name website.com.crt
    #output looks something like this

    Data was signed using PKCS1_v1_5 from Crypto.Signature. The signature is
Nk86W87PuLIpXg_PMVEsCU0YDccLrNDGui52kvUtu11G1Ew8LYMQ_17u5npbhCLpUDfBPf7CdVsaFDvdNVDhcH39XgKQ9G6jWNIye1L-NxGwP3aeFPt-1vNBfP6SdNARTpOHCtxsK5r3mW2HQsFWpJ-gJK6r5hQEy24N_HxZL9G3xOSgjgRiJ9LDUhRf9CUzkRkmCg1X2T0Nmq4Oq7Qksn3M1q99s0KLL4-Ino9ZOTfDKDVgdaU5G76SeBWndeFQEFrjpW1iXfORt4JCkcCi0YtPKMzd4Nu4VdB9znNX6QzEEjhgYFAkchvKdYgSHJClUlbuZKwDhC-iC7Im66Z-Lw==

    To verify with PKCS1_v1_5 from Crypto.Signature execute

    /usr/bin/env python rsa-sig-check.py --debug --data "Some message to sign" --verify --signature "Nk86W87PuLIpXg_PMVEsCU0YDccLrNDGui52kvUtu11G1Ew8LYMQ_17u5npbhCLpUDfBPf7CdVsaFDvdNVDhcH39XgKQ9G6jWNIye1L-NxGwP3aeFPt-1vNBfP6SdNARTpOHCtxsK5r3mW2HQsFWpJ-gJK6r5hQEy24N_HxZL9G3xOSgjgRiJ9LDUhRf9CUzkRkmCg1X2T0Nmq4Oq7Qksn3M1q99s0KLL4-Ino9ZOTfDKDVgdaU5G76SeBWndeFQEFrjpW1iXfORt4JCkcCi0YtPKMzd4Nu4VdB9znNX6QzEEjhgYFAkchvKdYgSHJClUlbuZKwDhC-iC7Im66Z-Lw=="  --cert-name website.com.crt 

    Data was signed using the private key of the issuer. The signature is
hV2LtZy0zOZnXxwKhJkqU3rH0vsnab6Wkdybjdu8n6K7xjqzIr-c1pZvannP1suF5PXcooUfFZSfYC8PPGygtc2z4TOEtyYB3sV71mBQna7x5zwRinhf4pBTIDXkWqgm1bvQk4iKy_WiDGAPLBdafDPdq6bzMiVRYU0zufr5turod4afeZLt7mBVllIqJEeqUUs42GNO-HH_NMe4YfrKzYi1GJWRbfiAwHsB9ey764hKG-qVUImzqOQn3gxwgg6vlMomV2BCGWuir3wvlwVuly_8gG502BRZ3ZlTpy1KkIE_OzHRU0pTD9krOSiQLwvunUD8z3hEOPYEVTySLQ2m9g==


    To verify with the signers public key execute

    /usr/bin/env python rsa-sig-check.py --debug --data "Some message to sign" --verify --signature "hV2LtZy0zOZnXxwKhJkqU3rH0vsnab6Wkdybjdu8n6K7xjqzIr-c1pZvannP1suF5PXcooUfFZSfYC8PPGygtc2z4TOEtyYB3sV71mBQna7x5zwRinhf4pBTIDXkWqgm1bvQk4iKy_WiDGAPLBdafDPdq6bzMiVRYU0zufr5turod4afeZLt7mBVllIqJEeqUUs42GNO-HH_NMe4YfrKzYi1GJWRbfiAwHsB9ey764hKG-qVUImzqOQn3gxwgg6vlMomV2BCGWuir3wvlwVuly_8gG502BRZ3ZlTpy1KkIE_OzHRU0pTD9krOSiQLwvunUD8z3hEOPYEVTySLQ2m9g=="  --cert-name website.com.crt 

3)  Verify to signature for a given message with the signers public key. This
    key we extract from the cert. Here we try to verify both sig types from above

    #/usr/bin/env python rsa-sig-check.py --debug --data "Some message to sign" --verify --signature "Nk86W87PuLIpXg_PMVEsCU0YDccLrNDGui52kvUtu11G1Ew8LYMQ_17u5npbhCLpUDfBPf7CdVsaFDvdNVDhcH39XgKQ9G6jWNIye1L-NxGwP3aeFPt-1vNBfP6SdNARTpOHCtxsK5r3mW2HQsFWpJ-gJK6r5hQEy24N_HxZL9G3xOSgjgRiJ9LDUhRf9CUzkRkmCg1X2T0Nmq4Oq7Qksn3M1q99s0KLL4-Ino9ZOTfDKDVgdaU5G76SeBWndeFQEFrjpW1iXfORt4JCkcCi0YtPKMzd4Nu4VdB9znNX6QzEEjhgYFAkchvKdYgSHJClUlbuZKwDhC-iC7Im66Z-Lw=="  --cert-name website.com.crt 

    Attempting to verify signature with RSA method
    verification was unsuccessful with RSA public key of signer

    Attempting to verify signature with PKCS1_v1_5 method
    verification was successful with PKCS1_v1_5 from Crypto.Signature

    #/usr/bin/env python rsa-sig-check.py --debug --data "Some message to sign" --verify --signature "hV2LtZy0zOZnXxwKhJkqU3rH0vsnab6Wkdybjdu8n6K7xjqzIr-c1pZvannP1suF5PXcooUfFZSfYC8PPGygtc2z4TOEtyYB3sV71mBQna7x5zwRinhf4pBTIDXkWqgm1bvQk4iKy_WiDGAPLBdafDPdq6bzMiVRYU0zufr5turod4afeZLt7mBVllIqJEeqUUs42GNO-HH_NMe4YfrKzYi1GJWRbfiAwHsB9ey764hKG-qVUImzqOQn3gxwgg6vlMomV2BCGWuir3wvlwVuly_8gG502BRZ3ZlTpy1KkIE_OzHRU0pTD9krOSiQLwvunUD8z3hEOPYEVTySLQ2m9g=="  --cert-name website.com.crt 
    Attempting to verify signature with RSA method
    verification was successful with RSA public key of signer

    Attempting to verify signature with PKCS1_v1_5 method
    verification was unsuccessful with PKCS1_v1_5 from Crypto.Signature


4)  You might not want to use some external certificate for verification
    or a special private key even.  In this case omit the --cert-name option
    completely and I'll generate you a self signed certificate and associated
    key pair instead. This will be used by default then.


    #output
    Creating self signed certificate and key pair, details as follows
    certificate name:      keys/certificate.crt
    cert private key:  keys/certificate.pem
    cert public  key:  keys/certificate.key.pub
    Created  self signed certificate and key pair

    #python rsa-sig-check.py --data "Some message" --sign
    #python rsa-sig-check.py --data "Some message" --verify --signature b64sig

"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert-name",
                        help="Supply your own X509 certificate to use",
                        required=False)
    parser.add_argument("--cert-dir",
                        help="Directory to look in for certs",
                        required=False)
    parser.add_argument("--private-key",
                        help="Supply your own X509 certificate to use",
                        required=False)
    parser.add_argument("--sign", dest='sign',
                        action='store_true',
                        help="Sign a message with given X509 certificate",
                        required=False)
    parser.add_argument("--verify", dest='verify', action='store_true',
                        help="Verify a signed message sig", required=False)
    parser.add_argument("--signature", help="The sig is base64 urlencoded",
                        required=False)
    parser.add_argument("--url", help="Save a certificate locally from url",
                        required=False)
    parser.add_argument("--debug", help="Print some debug info", dest='debug',
                        action='store_true', required=False)
    parser.add_argument("--data", default="This is my message",
                        help="A text message to sign", required=False)
    args = parser.parse_args()
    debug = args.debug

    args_dict = dict((k, v) for k, v in vars(args).iteritems() if v)

    u""" just grap the ssl cert from url and saved it locally """
    if args.url:
        get_cert_from_url(args.url, **args_dict)
        sys.exit(0)

    elif args.sign:
        u""" sign some data first with the pkcs1_v1_5 method then... """
        args_dict['use_pkcs1_v1_5'] = True
        sign_data(args.data, **args_dict)
        u""" sign some data just with a RSA private key normally """
        args_dict['use_pkcs1_v1_5'] = False
        sign_data(args.data, **args_dict)
        sys.exit(0)

    elif args.verify and args.signature:
        u""" given a signature, we try to verify it both ways. Only
        one will be succesful """
        try:
            p("Attempting to verify signature with RSA method")
            signature_bytes = urlsafe_b64decode(maybe_pad(args.signature))
            u""" the RSA sig verify expects the signature to be a tuple of length 1
            and the signature value as a long """
            signature_as_long = bytes_to_long(signature_bytes)
            args_dict['signature'] = signature_as_long
            verify_data(args.data, **args_dict)

            p("Attempting to verify signature with PKCS1_v1_5 method")
            u""" the pkcs1_v1_5 sig verify expects the signature to be a bytestring """
            signature_bytes = urlsafe_b64decode(maybe_pad(args.signature))
            args_dict['signature'] = signature_bytes
            args_dict['use_pkcs1_v1_5'] = True
            verify_data(args.data, **args_dict)

            sys.exit(0)

        except TypeError as e:
            print("Sig expected to be urlsafe_b64encoded: Exception %s" % (e))
            sys.exit(1)
        except Exception as e:
            print("Exception verifing by signature: %s" % e)
            sys.exit(1)
