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
import stat
import tempfile
import unittest
from unittest import mock

from subiquity.server.controllers.homenode_token import HomenodeTokenController


class TestTokenFilePerms(unittest.TestCase):
    """AKHN-240: the installer writes the installation key and install_id to
    /tmp; they must be owner-only (0600), not world-readable (0644)."""

    def _controller(self):
        # Bypass __init__ (it builds the Akash API client / does network setup);
        # we only exercise the file-writing helpers.
        return HomenodeTokenController.__new__(HomenodeTokenController)

    def test_token_written_0600(self):
        path = os.path.join(tempfile.mkdtemp(), "token")
        with mock.patch(
            "subiquity.server.controllers.homenode_token.TOKEN_FILE", path
        ):
            self._controller()._save_token("secret-installation-key")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_install_id_written_0600(self):
        path = os.path.join(tempfile.mkdtemp(), "install_id")
        with mock.patch(
            "subiquity.server.controllers.homenode_token.INSTALL_ID_FILE", path
        ):
            self._controller()._save_install_id("11111111-2222-3333-4444")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_tightens_preexisting_loose_file(self):
        # A pre-existing world-readable file must be tightened, not left as-is.
        path = os.path.join(tempfile.mkdtemp(), "token")
        with open(path, "w") as f:
            f.write("stale")
        os.chmod(path, 0o644)
        with mock.patch(
            "subiquity.server.controllers.homenode_token.TOKEN_FILE", path
        ):
            self._controller()._save_token("fresh")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path) as f:
            self.assertEqual(f.read(), "fresh")
