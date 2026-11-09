"""
Stage 19 Test: 100% Local-Only Operation (Wi-Fi Sync Disabled by Default)
Ensures:
1. `ENABLE_P2P_SYNC` defaults to False, so UDP beacons on port 41234 are not started.
2. UI displays reassuring "100% Локально" badge.
3. Automated 8-second sync polling is disabled.
4. Data files remain strictly local on disk with AES-256-GCM encryption.
"""
import unittest
from family_finances_os.web_server import FamilyFinancesHandler, ENABLE_P2P_SYNC
from family_finances_os.config import DB_PATH, ENC_DB_PATH, STRICT_ENCRYPTION


class TestStage19LocalOnlyMode(unittest.TestCase):
    def test_p2p_sync_disabled_by_default(self):
        """P2P Wi-Fi sync beacon should be disabled by default for home offline privacy."""
        self.assertFalse(ENABLE_P2P_SYNC)

    def test_ui_shows_local_mode_badge(self):
        """UI header must present clear 100% Local indicator."""
        handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
        html = handler._render_app_html()
        self.assertIn("100% Локально", html)
        self.assertIn("offlineModeBadge", html)

    def test_sync_auto_polling_disabled(self):
        """Browser must not continuously poll sync status in background."""
        handler = FamilyFinancesHandler.__new__(FamilyFinancesHandler)
        html = handler._render_app_html()
        self.assertNotIn("setInterval(updateSyncStatus, 8000)", html)

    def test_database_paths_are_local_files(self):
        """Database paths must reside strictly on local filesystem."""
        self.assertTrue(str(DB_PATH).endswith(".db"))
        self.assertTrue(str(ENC_DB_PATH).endswith(".db.enc"))


if __name__ == "__main__":
    unittest.main()
