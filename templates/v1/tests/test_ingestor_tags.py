import unittest

from stages.ingestor import detect_external_input, detect_integer_arith_untrusted, should_exclude_path


class IngestorTagTests(unittest.TestCase):
    def test_directory_filter_default_on_library(self):
        self.assertTrue(should_exclude_path('contrib/demo.c', is_library_target=True))
        self.assertFalse(should_exclude_path('src/core.c', is_library_target=True))

    def test_external_input_target_aware(self):
        self.assertTrue(detect_external_input('n = recv(fd, buf, len, 0);', is_library_target=True))
        self.assertFalse(detect_external_input('int len = 0; // local only', is_library_target=True))

    def test_integer_arith_needs_untrusted_signal(self):
        self.assertFalse(detect_integer_arith_untrusted('size = len + 4;'))
        self.assertTrue(detect_integer_arith_untrusted('size = len + 4; n = recv(fd, buf, len, 0);'))


if __name__ == '__main__':
    unittest.main()
