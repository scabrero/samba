# Unix SMB/CIFS implementation.
#
# Tests for samba.http.
#
# Copyright (C) 2026
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from samba import http
import samba.tests


class HttpHeaderTests(samba.tests.TestCase):

    def test_add_header(self):
        headers = [("User-Agent", "Samba/http_test")]
        updated = http.add_header(headers, "Accept", "*/*")
        self.assertEqual(headers, [("User-Agent", "Samba/http_test")])
        self.assertEqual(updated, [
            ("User-Agent", "Samba/http_test"),
            ("Accept", "*/*"),
        ])

    def test_replace_header_case_insensitive(self):
        headers = [
            ("User-Agent", "Samba/http_test"),
            ("Accept", "*/*"),
        ]
        updated = http.replace_header(headers, "accept", "application/json")
        self.assertEqual(updated, [
            ("User-Agent", "Samba/http_test"),
            ("Accept", "application/json"),
        ])

    def test_remove_header(self):
        headers = [
            ("User-Agent", "Samba/http_test"),
            ("Accept", "*/*"),
        ]
        updated = http.remove_header(headers, "Accept")
        self.assertEqual(updated, [("User-Agent", "Samba/http_test")])

    def test_remove_header_missing(self):
        with self.assertRaises(KeyError):
            http.remove_header([], "Accept")

    def test_invalid_header_key(self):
        with self.assertRaises(ValueError):
            http.add_header([], "Bad\nKey", "value")

    def test_invalid_header_value(self):
        with self.assertRaises(ValueError):
            http.replace_header([], "Accept", "bad\r\nvalue")
