from __future__ import annotations

from cryptohawk.api.auth import inventory
from cryptohawk.storage.continuous import ContinuousRepository

continuous_repo = ContinuousRepository(inventory)
