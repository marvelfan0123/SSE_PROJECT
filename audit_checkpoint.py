"""Optional external HMAC checkpoints for the local audit chain.

Keep VULNGRAPH_AUDIT_CHECKPOINT_KEY and checkpoint file outside the SQLite
storage and back them up independently. This detects tampering only if the
key and checkpoint cannot be rewritten by the attacker.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path


def _secret():
    secret = os.environ.get('VULNGRAPH_AUDIT_CHECKPOINT_KEY') or os.environ.get('AUDIT_CHECKPOINT_SECRET', '')
    if len(secret) < 32:
        raise RuntimeError('Set VULNGRAPH_AUDIT_CHECKPOINT_KEY (or AUDIT_CHECKPOINT_SECRET) to a secret of at least 32 characters')
    return secret.encode('utf-8')


def _path():
    name = os.environ.get('VULNGRAPH_AUDIT_CHECKPOINT_FILE', '')
    if not name:
        raise RuntimeError('Set VULNGRAPH_AUDIT_CHECKPOINT_FILE to an external protected path')
    return Path(name).expanduser().resolve()


def _mac(payload):
    data = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    return hmac.new(_secret(), data, hashlib.sha256).hexdigest()


def create_checkpoint(verification):
    if not verification.get('valid'):
        raise ValueError('Cannot checkpoint an invalid audit chain')
    payload = {'checked': int(verification['checked']), 'last_hash': verification['last_hash'], 'format': 1}
    result = {'payload': payload, 'hmac_sha256': _mac(payload)}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # A separate file is not by itself tamper resistant; OS ACLs and backups matter.
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    return result


def verify_checkpoint(verification):
    path = _path()
    try:
        saved = json.loads(path.read_text(encoding='utf-8'))
        payload = saved['payload']
        if not hmac.compare_digest(saved['hmac_sha256'], _mac(payload)):
            return {'valid': False, 'reason': 'Checkpoint signature mismatch'}
        if not verification.get('valid'):
            return {'valid': False, 'reason': 'Audit chain verification failed'}
        if verification.get('checked') != payload['checked'] or verification.get('last_hash') != payload['last_hash']:
            return {'valid': False, 'reason': 'Audit chain differs from trusted checkpoint'}
        return {'valid': True, 'checked': payload['checked']}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {'valid': False, 'reason': 'Checkpoint unavailable or malformed: ' + type(exc).__name__}
