# Copyright 2026 Canonical, Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import tempfile
import unittest
from unittest import mock

from subiquity.common import errorreport
from subiquity.common.errorreport import redact_secrets


class TestRedactSecrets(unittest.TestCase):
    """AKHN-243: the installer journal is captured verbatim into crash reports
    (recent_syslog(re.compile("."))). Strip the installation key, install_id,
    and auth headers before they're attached."""

    def test_redacts_the_on_disk_installation_key(self):
        with tempfile.TemporaryDirectory() as d:
            tok = os.path.join(d, "token")
            with open(tok, "w") as f:
                f.write("five-word-installation-key-value\n")
            with mock.patch.object(errorreport, "_SECRET_FILES", (tok,)):
                out = redact_secrets(
                    "subiquity: verifying five-word-installation-key-value ok"
                )
        self.assertNotIn("five-word-installation-key-value", out)
        self.assertIn("[REDACTED]", out)

    def test_redacts_the_on_disk_install_id(self):
        with tempfile.TemporaryDirectory() as d:
            iid = os.path.join(d, "install_id")
            with open(iid, "w") as f:
                f.write("11111111-2222-3333-4444-555555555555")
            with mock.patch.object(errorreport, "_SECRET_FILES", (iid,)):
                out = redact_secrets(
                    "install_id=11111111-2222-3333-4444-555555555555"
                )
        self.assertNotIn("11111111-2222-3333-4444-555555555555", out)
        self.assertIn("[REDACTED]", out)

    def test_redacts_bearer_header(self):
        out = redact_secrets("Authorization: Bearer abc123.payload.signature x")
        self.assertNotIn("abc123.payload.signature", out)
        self.assertIn("Authorization: Bearer [REDACTED]", out)

    def test_redacts_jwt_anywhere(self):
        out = redact_secrets("tok=eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMeK done")
        self.assertNotIn("eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMeK", out)

    def test_does_not_over_redact_plain_lines(self):
        line = "Starting installation step 3 of 5 (downloading base system)"
        self.assertEqual(redact_secrets(line), line)

    def test_empty_passthrough(self):
        self.assertEqual(redact_secrets(""), "")
        self.assertIsNone(redact_secrets(None))
