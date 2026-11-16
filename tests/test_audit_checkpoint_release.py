import json
import os
import tempfile
import unittest
from unittest.mock import patch
from audit_checkpoint import create_checkpoint, verify_checkpoint

class AuditCheckpointReleaseTests(unittest.TestCase):
    def test_checkpoint_and_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            env={'VULNGRAPH_AUDIT_CHECKPOINT_KEY':'a'*48,'VULNGRAPH_AUDIT_CHECKPOINT_FILE':directory+'/checkpoint.json'}
            with patch.dict(os.environ, env):
                record={'valid':True,'checked':3,'last_hash':'123abc'}
                create_checkpoint(record)
                self.assertTrue(verify_checkpoint(record)['valid'])
                self.assertFalse(verify_checkpoint({**record,'checked':2})['valid'])
                path=env['VULNGRAPH_AUDIT_CHECKPOINT_FILE']
                with open(path, encoding='utf-8') as f: data=json.load(f)
                data['payload']['checked']=5
                with open(path,'w') as f: json.dump(data,f)
                self.assertFalse(verify_checkpoint(record)['valid'])

    def test_no_secret_rejected(self):
        with patch.dict(os.environ, {'VULNGRAPH_AUDIT_CHECKPOINT_KEY':'short','VULNGRAPH_AUDIT_CHECKPOINT_FILE':'/tmp/never-write.json'}):
            with self.assertRaises(RuntimeError):
                create_checkpoint({'valid':True,'checked':0,'last_hash':'GENESIS'})
