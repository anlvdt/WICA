# -*- coding: utf-8 -*-
"""Unit tests cho fast_commands.py — regex parser.

Chạy: python -m pytest tests/test_fast_commands.py -v
"""
import sys
import os
import unittest

# Thêm parent dir vào path — cho phép import fast_commands
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from fast_commands import parse_fast, _split_packages, _looks_like_path


class TestInstallCommands(unittest.TestCase):
    """Test nhận diện lệnh install."""

    def test_install_single(self):
        result = parse_fast("cài chrome")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "install")
        self.assertEqual(result[0]["package"], "chrome")

    def test_install_english(self):
        result = parse_fast("install firefox")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "install")
        self.assertEqual(result[0]["package"], "firefox")

    def test_install_multi(self):
        result = parse_fast("cài chrome, firefox, 7zip")
        self.assertIsNotNone(result)
        self.assertEqual(len(result), 3)
        for a in result:
            self.assertEqual(a["type"], "install")

    def test_install_vn(self):
        result = parse_fast("cài đặt notepad++")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "install")


class TestUninstallCommands(unittest.TestCase):
    """Test nhận diện lệnh uninstall."""

    def test_uninstall_basic(self):
        result = parse_fast("gỡ chrome")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "uninstall")

    def test_uninstall_english(self):
        result = parse_fast("uninstall firefox")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "uninstall")


class TestSearchCommands(unittest.TestCase):
    """Test nhận diện lệnh search."""

    def test_search_vn(self):
        result = parse_fast("tìm chrome")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "search")

    def test_search_english(self):
        result = parse_fast("search firefox")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "search")


class TestSystemConfigCommands(unittest.TestCase):
    """Test nhận diện lệnh cấu hình hệ thống."""

    def test_dark_mode(self):
        result = parse_fast("bật dark mode")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "system_config")
        self.assertEqual(result[0]["config"], "dark_mode")

    def test_light_mode(self):
        result = parse_fast("light mode")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["config"], "light_mode")

    def test_show_file_ext(self):
        result = parse_fast("hiện đuôi file")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["config"], "show_file_ext")

    def test_uac_off(self):
        """'tắt uac' is a quick command — not detected by regex alone."""
        qc = {"tắt uac": {"action": {"type": "system_config", "config": "uac_off"}}}
        result = parse_fast("tắt uac", qc)
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["config"], "uac_off")


class TestCLICommands(unittest.TestCase):
    """Test nhận diện lệnh CLI whitelist."""

    def test_ipconfig(self):
        result = parse_fast("ipconfig /all")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "cli")
        self.assertEqual(result[0]["command"], "ipconfig /all")

    def test_ping(self):
        result = parse_fast("ping google.com")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "cli")

    def test_hostname(self):
        result = parse_fast("hostname")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "cli")


class TestProfileCommands(unittest.TestCase):
    """Test nhận diện lệnh profile."""

    def test_run_profile(self):
        result = parse_fast("chạy profile mac_dinh")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "run_profile")
        self.assertEqual(result[0]["name"], "mac_dinh")

    def test_list_profiles(self):
        result = parse_fast("danh sách profile")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "list_profiles")


class TestSpecialActions(unittest.TestCase):
    """Test lệnh đặc biệt."""

    def test_bloatware(self):
        """'gỡ bloatware' requires quick_commands to detect as remove_bloatware."""
        qc = {"gỡ bloatware": {"action": {"type": "remove_bloatware"}}}
        result = parse_fast("gỡ bloatware", qc)
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "remove_bloatware")

    def test_list_installed(self):
        result = parse_fast("danh sách phần mềm")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "list_installed")

    def test_system_info(self):
        result = parse_fast("thông tin hệ thống")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "system_info")

    def test_upgrade_all(self):
        result = parse_fast("cập nhật tất cả")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "upgrade_all")


class TestQuickCommands(unittest.TestCase):
    """Test quick commands từ config."""

    def test_quick_command_match(self):
        qc = {
            "teamviewer qs": {
                "action": {"type": "deploy_portable", "source": "TV.exe", "dest": "C:\\Tools\\TV", "name": "TeamViewer QS"}
            }
        }
        result = parse_fast("teamviewer qs", qc)
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "deploy_portable")

    def test_quick_command_no_match(self):
        qc = {"teamviewer qs": {"action": {"type": "deploy_portable"}}}
        # "random text" should NOT match quick commands
        result = parse_fast("xin chào", qc)
        self.assertIsNone(result)


class TestHelperFunctions(unittest.TestCase):
    """Test helper functions."""

    def test_split_packages_comma(self):
        result = _split_packages("chrome, firefox, 7zip")
        self.assertEqual(len(result), 3)
        self.assertIn("chrome", result)

    def test_split_packages_and(self):
        result = _split_packages("chrome và firefox")
        self.assertEqual(len(result), 2)

    def test_looks_like_path(self):
        self.assertTrue(_looks_like_path("C:\\Users\\test"))
        self.assertTrue(_looks_like_path("D:\\folder\\file.exe"))
        self.assertFalse(_looks_like_path("chrome"))
        self.assertFalse(_looks_like_path("install firefox"))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases."""

    def test_empty_input(self):
        result = parse_fast("")
        self.assertIsNone(result)

    def test_whitespace_only(self):
        result = parse_fast("   ")
        self.assertIsNone(result)

    def test_unknown_command(self):
        result = parse_fast("abcdef12345")
        self.assertIsNone(result)

    def test_case_insensitive_cli(self):
        result = parse_fast("IPCONFIG")
        self.assertIsNotNone(result)
        self.assertEqual(result[0]["type"], "cli")


if __name__ == "__main__":
    unittest.main()
