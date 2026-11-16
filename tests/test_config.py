import os
import tempfile
import unittest
from pathlib import Path
from config import load_environment

class ConfigTests(unittest.TestCase):
    def test_loads_env_values_without_overwriting_existing_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("VULNX_TEST_CONFIG=from-file\nVULNX_TEST_KEEP=from-file\n", encoding="utf-8")
            os.environ["VULNX_TEST_KEEP"] = "existing"
            os.environ.pop("VULNX_TEST_CONFIG", None)
            load_environment(path)
            self.assertEqual(os.environ["VULNX_TEST_CONFIG"], "from-file")
            self.assertEqual(os.environ["VULNX_TEST_KEEP"], "existing")
            os.environ.pop("VULNX_TEST_CONFIG", None)
            os.environ.pop("VULNX_TEST_KEEP", None)

if __name__ == "__main__": unittest.main()
