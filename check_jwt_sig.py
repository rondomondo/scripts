#!/usr/bin/env python
import os
import re
import time
import json
import base64
import requests
import argparse

from base64 import urlsafe_b64decode, b64decode
from Crypto.Hash import SHA256, SHA512
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

import jwt

u"""
Two methods/examples of how to decode and verify the signature of AWS cognito JWT web tokens externally
"""

def maybe_pad(s):
    return (s + '=' * (4 - len(s) % 4))


def get_token_segments(token):
    u"""
    A valid token will have at least two seqments. Segments are delimited by
    a period '.'
    """
    header, payload, signature = token.split(".")

    u"""
    The JWT spec tells us the header MUST be urlsafe B64 encoded. Decode it
    but first add any padding (by adding one or more =) that may be needed

    https://tools.ietf.org/html/rfc7519

    Get the header json object that was stringified, it will be returned a
    string of bytes
    """
    header_json_str = urlsafe_b64decode(maybe_pad(header))

    u"""
    get the payload json object that was stringified, it will be returned a
    string of bytes
    """

    payload_json_str = urlsafe_b64decode(maybe_pad(payload))

    u"""
    get the signature that was stringified, it will be returned a string of
    bytes. It is not an object but rather the signature byte string, so full
    of non printable characters
    """

    signature_bytes = urlsafe_b64decode(maybe_pad(signature))

    u"""
    convert header and payload back into objects. The signature is already
    a byte string


    NB: The order of the keys in the dict/object that results from the
    json.loads call will not be ordered in any way so watch out if you
    expect the transformations to be reversable

    object -> json.dumps -> string  <==> string -> json.loads -> object

    This can trip you up if you decode a header and payload, then try to recode
    it and expect the signature to work out.
    """

    header_json = json.loads(header_json_str, 'utf-8')
    payload_json = json.loads(payload_json_str, 'utf-8')
    return header_json, payload_json, signature_bytes


def get_claim(token, name, debug=False):
    payload_json = get_token_segments(token)[1]
    value = payload_json.get(name.lower(), None)
    if debug:
        if value is None:
            print("Claim '%s' was not present" % (name))
        else:
            print("Claim '%s' contains: %s" % (name, value))
        if name.lower == 'exp':
            print "Time now: %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                                  time.localtime(time.time())))
            print "Expires:  %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                                  time.localtime(value)))
    return value

testtoken = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkhnR0NMQlZNRXBaVG82SUFDM3ZVVWphZCJ9.eyJpc3MiOiJodHRwczovL2F1dGgwLW1vY2suYXdjaHEuY29tLyIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJodHRwczovL2VuZ2FnZW1lbnQtY2FuYXJ5LmF3Y2hxLmNvbSIsImh0dHBzOi8vYXdjaHEuYXUuYXV0aDAuY29tL3VzZXJpbmZvIl0sImF6cCI6Im1UbWp5bkJJVkFmemR1NVgybjVQTEZ6bUFNRjdMRENuIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCBhZGRyZXNzIHBob25lIG9mZmxpbmVfYWNjZXNzIiwiZ3R5IjoicGFzc3dvcmQiLCJpYXQiOjE1MjY5NDg5NTQsImV4cCI6MTUyNjk1Nzk1NCwic3ViIjoiYXV0aDB8VzNpY0F6aUpnSkwxOHoycnp5UnBSWkhhIn0.CHWDh6iuAXLdijp49fyo27mvthsD3KipRQGMcfsnAng7P1Edgh7nD_5IhS6fOeYzJ8hqqIk8QfaoXUQq2zoEaCDH9iY4r6ICdSB-hZA5KgYjd3XtvQxCvhd5GDznD1Zg2dJHnEwI_okOaWRNz76QsyGgvAT_Vc1jaxS-MMg5zB5lNYUYCX1xZTVYrMK-wB5NN2CbYxH3HGhODIGAMf3rEEdfSV9DC5HO71w-3uHCpn1eFfxva8Uyt0eWJOaKRdscoGcRSuRqsQMAFH3zSVjTyKuNNILOtRGz6urd38rKU0IH4gAHa8ui2my1Aq4poku9xlkwlxiaX2MXf9x9vwxAkw'


def get_header(token, name, debug=False):
    payload_json = get_token_segments(token)[0]
    value = payload_json.get(name.lower(), None)
    if debug:
        if value is None:
            print("Header '%s' was not present" % (name))
        else:
            print("Header '%s' contains: %s" % (name, value))
    return value


def get_EXP(token):
    payload_json = get_token_segments(token)[1]
    exp = payload_json.get('exp', None)
    print "Time now: %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                          time.localtime(time.time())))
    print "Expires:  %s" % (time.strftime('%Y-%m-%d %H:%M:%S',
                                          time.localtime(exp)))
    return exp


def get_AUD(token):
    payload_json = get_token_segments(token)[1]
    aud = payload_json.get('aud', None)
    return aud


def get_ISS(token):
    payload_json = get_token_segments(token)[1]
    iss = payload_json.get('iss', None)
    return iss


def get_ALG(token):
    header_json = get_token_segments(token)[0]
    alg = header_json['alg']
    return alg


def get_KID(token):
    header_json = get_token_segments(token)[0]
    kid = header_json['kid']
    return kid


def get_modulus_and_exponant(jwk_sets, kid, algorithm, force_fail=False):
    print("Looking for kid=%s algo=%s in the jwt key sets" % (kid, algorithm))
    for jwks in jwk_sets['keys']:
        if (force_fail and jwks['kid'] != kid) or (jwks['kid'] == kid and
                                                   jwks['alg'] == algorithm):
            e_b64 = jwks['e']
            n_b64 = jwks['n']
            e_bytes = b64decode(e_b64)
            n_bytes = b64decode(n_b64)
            exponant = bytes_to_long(e_bytes)
            modulus = bytes_to_long(n_bytes)
            return modulus, exponant


def get_jwks_json(token):
    iss = get_claim(token, "iss")
    if iss is None:
        print("No issuer found in token")
        return
    else:
        m = re.match(("https?:\/\/"), iss)
        if m:
            scheme = m.group(0)
            iss = iss.replace(scheme, "")
            jwks_names = ["jwks_uri", "jwks.json"]
            for i, jwks_name in enumerate(jwks_names):
                url = ("/").join([iss, '.well-known', jwks_name])
                url = scheme + os.path.normpath(("/").join([iss, '.well-known', jwks_name]))
                
                print("checking jwks_uri url (%s): %s" % (i, url))
                hfn = SHA256.new(url).hexdigest()
                if not os.path.exists("/tmp/%s" % (hfn)):
                    r = requests.get(url)
                    if r.status_code == 200:
                        with open("/tmp/%s" % (hfn), "w") as outfile:
                            outfile.write(json.dumps(r.json()))
                            return r.json()
                else:
                    with open("/tmp/%s" % (hfn), "r") as infile:
                        return json.loads(infile.read())


def construct_RSA_publickey(exponant, modulus):
    publicKey = RSA.construct((exponant, modulus))
    return publicKey.publickey().exportKey(), publicKey.publickey()


def main(token, verify=True):
    u"upstream base64 decode routines expect str types so convert if needed"
    if type(token) == unicode:
        token = token.encode('utf-8')
    u"""
    Extract the KeyID and some other useful information to validate the token.

    See...

    http://self-issued.info/docs/draft-jones-json-web-token-01.html#ReservedClaimName

    Note: For other than this demo case, in real world uses we would obviously
    not check the validity of AUD, ISS against itself but rather values you
    expect


    """
    #alg = get_ALG(token)
    #aud = get_AUD(token)
    alg = get_header(token, 'alg', True)
    kid = get_header(token, 'kid', True)
    get_claim(token, 'exp', True)
    aud = get_claim(token, 'aud', True)
    get_claim(token, 'iss', True)
    #kid = get_KID(token)
    #get_EXP(token)
    #get_ISS(token)

    u"""
    The AWS Cognito JWT is digitally signed by the private key
    half of the ISSUERS RSA key pair. We can find who the ISSUER
    was by looking for the 'iss' key in payload.  To verify the token
    signature there are a few basic steps.

    Step 1:

    Get the corrosponding Public Key half of the RSA key pair that
    signed the token.

    We get it from the URL addressed via:

    ISS + '/.well-known/jwks_uri'
    ie: https://cognito-identity.amazonaws.com/.well-known/jwks_uri
    """
    jwk_sets = get_jwks_json(token)

    u"""
    The particular key we want is the key set that matches the 'kid' in the
    token header.  It'll look something like this:

    {
        "kty": "RSA",
        "alg": "RS512",
        "use": "sig",
        "kid": "ap-southeast-22",
        "n": "AJZzNUBnF1H6rFFiqJbiziWW7VVbyo............Ws35b7",
        "e": "AQAB"
    }

    Step 2:

    Note the key type and hash algorithm. Extract the modulus
    (the n value) and the exponant (the e value) from the key set
    """

    modulus, exponant = get_modulus_and_exponant(jwk_sets, kid, alg)

    u""" Using the modulus and exponant construct the Public key and
    return it in PEM format. It will look something like this:

    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi8sT+HiH1d0BXLLQLt+f
    Vldnca3phPYs+weygJQaA8BUmcsmM9GPd1IjZSaVZotpxKgdh4UAF/GPxhE6cT1+
    mIa2jktx3J+5EoRP02/lRpmnSQxJKgXvBeKenTsAJRuf5kTciZBHXqvX9D+PcAPg
    KY3uBWOTn4RnNUJNC0DMlknz8SAI8UThgDRDZSAW0GNme3hIjxOWOKQGpSY0NUrK
    OHbIj6bh9A78tk4Roj9oY5Zh6fhGs77/eFNiTvdv6gUI+cinWws1SZ0AfOMiBZgI
    LaoHAL61FaLvTrl5rYpiP6Q00V69cVgyumHdTWbGoNlLMg68RciVmqWE6g5zk2ZY
    xwIDAQAB
    -----END PUBLIC KEY-----
    """

    pem, publicKey = construct_RSA_publickey(modulus, exponant)

    u"""

    Step 3a

    Using the pyjwt module we can now try to decode & verify the token
    #pip install pyjwt

    Use the correct AUD, PEM etc., values below as required. In this case they will
    always be right because we just extrated from the token itself.

    """
    try:
        payload_decoded_and_verified = jwt.decode(token, pem, audience=aud,
                                                  algorithms=[alg], verify=verify)
    except Exception as ex:
        print(ex)
        return

    u"""
    possible errors/exceptions from pyjwt

    jwt.exceptions.ExpiredSignatureError: Signature has expired
    see the u'exp': 1483323209 value in the payload

    jwt.exceptions.DecodeError: Signature verification failed
    """

    if payload_decoded_and_verified:
        print ("verify successful.\npayload:\n%s\n" %
               (payload_decoded_and_verified))
    else:
        print ("verify failed")

    u"""

    Or, alternatively, using the PKCS1_v1_5 module you can also verify it.

    Step 3b

    Note: One thing to watch out for here is that the order of the keys in the
    header payload matters, so if you decode a header from a token to a dict eg
    dict = json.loads(base64.urlsafe_b64decode(header)) and then encode it back
    the order of the keys may be different as a python dict is unordered

    With that in mind,  using PKCS1_v1_5 we can try to verify
    """

    header_base64 = token.split(".")[0]
    payload_base64 = token.split(".")[1]
    signature_base64 = token.split(".")[-1]

    signature = base64.urlsafe_b64decode(maybe_pad(signature_base64))
    hash_object = SHA512.new(b'' + header_base64 + b'.' + b'' + payload_base64)

    verifier = PKCS1_v1_5.new(publicKey)

    u"""
    Notice here it is the hash object and not the digest that is supplied to verify
    """
    verified = verifier.verify(hash_object, signature)
    print ("Signature verification result using PKCS1_v1_5: %s" % (verified))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--token', help='a JWT or JWS token.', required=True)
    parser.add_argument('--no-verify', help="Don't bother verifing claims",
                        default=True, action='store_true')
    parser.add_argument('--debug', help="Dump some extra decode information",
                        default=False, action='store_true')
    args = parser.parse_args()

    main(args.token, args.no_verify)
