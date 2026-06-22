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

from unittest import mock

from subiquity.server.controllers.homenode_token import (
    HomenodeTokenController,
    log as controller_log,
)
from subiquitycore.tests import SubiTestCase
from subiquitycore.tests.mocks import make_app

LOGGER = "subiquity.server.controllers.homenode_token"


class TestCheckTokenLogging(SubiTestCase):
    """AKHN-243: the homenode-token controller must not log the installation
    key or install_id (not even a truncated prefix). The server debug/info logs
    are attached to crash reports verbatim (InstallerServerLog*), and
    redact_secrets — which only runs on the journal and only matches the FULL
    value — would not scrub a logged prefix. So nothing secret may be logged."""

    def _controller(self, *, install_id):
        # Bypass __init__ (akash_api setup + Windows-config read); wire only
        # what check_token_GET touches.
        c = HomenodeTokenController.__new__(HomenodeTokenController)
        c.app = make_app()
        c.app.base_model.network.has_network = True
        c.install_id = None
        c._save_install_id = mock.Mock()
        c.akash_api = mock.Mock()
        c.akash_api.verify_installation_key = mock.AsyncMock(
            return_value={"data": {"install_id": install_id, "message": "ok"}}
        )
        return c

    async def test_token_and_install_id_never_logged(self):
        token = "swift-amber-otter-quartz-maple"  # realistic 5-word key, >10 chars
        install_id = "inst_abcdef0123456789"
        controller = self._controller(install_id=install_id)

        with self.assertLogs(controller_log, level="INFO") as cm:
            answer = await controller.check_token_GET(token)

        logged = "\n".join(cm.output)
        # Neither the full secret nor any prefix of it may appear.
        self.assertNotIn(token, logged)
        self.assertNotIn(token[:10], logged)
        self.assertNotIn(install_id, logged)
        self.assertNotIn(install_id[:10], logged)
        # The flow is still observable (request logged) with a safe form.
        self.assertIn("check_token_GET", logged)
        self.assertIn(str(len(token)), logged)
        # Sanity: the happy path still ran.
        self.assertEqual(answer.status.name, "VALID_TOKEN")
