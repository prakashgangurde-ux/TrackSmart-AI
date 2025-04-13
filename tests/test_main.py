import unittest
from main import *
import sqlite3
from datetime import datetime

class TestTrackSmartAI(unittest.TestCase):
    def setUp(self):
        # Create test database connection
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        
        # Initialize test environment
        self.test_user = {
            'username': 'testuser',
            'password': 'testpass123',
            'email': 'test@example.com'
        }

    def tearDown(self):
        self.conn.close()

    def test_validate_email(self):
        self.assertTrue(validate_email("test@example.com"))
        self.assertFalse(validate_email("invalid-email"))
        self.assertFalse(validate_email(""))
        self.assertFalse(validate_email("@example.com"))

    def test_hash_password(self):
        password = "testpass123"
        hashed = hash_password(password)
        self.assertEqual(len(hashed), 64)  # SHA-256 produces 64 char hex string
        self.assertEqual(hash_password(password), hashed)  # Consistent results

    def test_validate_input(self):
        self.assertTrue(validate_input("user", "password123"))
        self.assertFalse(validate_input("us", "pass"))  # Too short
        self.assertFalse(validate_input("", ""))  # Empty input

    def test_ai_suggestion(self):
        suggestion = ai_suggestion()
        self.assertIsInstance(suggestion, str)
        self.assertGreater(len(suggestion), 0)

    def test_check_session(self):
        global current_user_id, session_start
        current_user_id = None
        self.assertFalse(check_session())
        
        current_user_id = 1
        session_start = datetime.now()
        self.assertTrue(check_session())

if __name__ == '__main__':
    unittest.main()