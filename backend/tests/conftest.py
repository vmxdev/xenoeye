import os
from pathlib import Path

TEST_DB = Path("/tmp/xenoeye-portal-test.db")
TEST_DB.unlink(missing_ok=True)
os.environ["XE_DATABASE_URL"] = f"sqlite:///{TEST_DB}"
os.environ["XE_BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["XE_BOOTSTRAP_ADMIN_PASSWORD"] = "TestPassword123!"
