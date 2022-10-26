import rsa
import base64


def _newkeys(nbits: int) -> (str, str):
    publickey, privatekey = rsa.newkeys(nbits)
    pub_key: str = base64.standard_b64encode(publickey.save_pkcs1("DER")).decode()
    priv_key: str = base64.standard_b64encode(privatekey.save_pkcs1("DER")).decode()
    return pub_key, priv_key


def rsa_encrypt(rsa_nbits: int, msg: str) -> (str, str, str):
    pub_key, priv_key = _newkeys(rsa_nbits)
    secret = _encrypt(msg, pub_key)
    return secret, pub_key, priv_key


def _encrypt(msg: str, pub_key: str) -> str:
    publickey: rsa.PublicKey = rsa.PublicKey.load_pkcs1(base64.standard_b64decode(pub_key.encode()), "DER")
    crypto: bytes = rsa.encrypt(msg.encode(), publickey)
    secret: str = base64.standard_b64encode(crypto).decode()
    return secret


def rsa_decrypt(secret: str, priv_key: str) -> str:
    text = _decrypt(secret, priv_key)
    return text


def _decrypt(secret: str, priv_key: str) -> str:
    privatekey: rsa.PrivateKey = rsa.PrivateKey.load_pkcs1(base64.standard_b64decode(priv_key.encode()), "DER")
    crypto: bytes = base64.standard_b64decode(secret.encode())
    text: str = rsa.decrypt(crypto, privatekey).decode()
    return text
