import unittest
from app.security import validate_path, InputRejected

class SecurityTests(unittest.TestCase):
    def test_accept_py(self): self.assertEqual(validate_path('src/a.py'),'src/a.py')
    def test_reject_traversal(self):
        with self.assertRaises(InputRejected): validate_path('../x.py')
    def test_reject_env(self):
        with self.assertRaises(InputRejected): validate_path('.env')
    def test_reject_binary(self):
        with self.assertRaises(InputRejected): validate_path('x.bin')
if __name__=='__main__': unittest.main()
