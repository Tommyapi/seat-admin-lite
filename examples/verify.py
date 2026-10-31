#!/usr/bin/env python3
import base64, json, sys
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError:
    print("cryptography not installed; skipped")
    raise SystemExit(0)
def canonical(v):
    if isinstance(v,dict): return {k:canonical(v[k]) for k in sorted(v)}
    if isinstance(v,list): return [canonical(x) for x in v]
    return v
def verify(public_key_pem, entitlement):
    key=serialization.load_pem_public_key(public_key_pem.encode())
    key.verify(base64.b64decode(entitlement['signature']),json.dumps(canonical(entitlement['payload']),ensure_ascii=False,separators=(',',':')).encode(),ec.ECDSA(hashes.SHA256()))
    return True
if __name__=='__main__':
    fixture=json.load(open(sys.argv[1] if len(sys.argv)>1 else 'examples/fixture.json',encoding='utf8'))
    print('verified' if verify(fixture['public_key'],fixture['entitlement']) else 'failed')
