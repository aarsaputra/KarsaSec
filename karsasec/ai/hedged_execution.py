"""Hedged Request Execution Coordinator for Sprint F11.7 (INV-F11-HEDGE-16, ADV-30..32).

Guarantees atomic winner selection among parallel hedged provider execution attempts.
Only exactly 1 provider attempt can win per request ID. Late provider responses are safely discarded
without double-charging budget or mutating request state.
"""

from datetime import UTC, datetime
import logging
from sqlalchemy import update
from sqlalchemy.orm import Session

from karsasec.persistence.models import AIRequestModel

logger = logging.getLogger("karsasec.ai.hedged_execution")


class HedgedExecutionCoordinator:
    """Atomic Winner Selection Coordinator for Hedged Request Execution."""

    @staticmethod
    def try_claim_winner(
        session: Session,
        request_id: str,
        provider_id: str,
        model_id: str | None = None,
    ) -> bool:
        """Atomically attempts to claim winner status for a hedged provider execution attempt.

        Enforces INV-F11-HEDGE-16:
        Only the first provider attempt to successfully claim the request's winner_provider column
        is designated as the winner. Subsequent claims for the same request_id return False.

        Args:
            session: Active database session.
            request_id: Unique request identifier.
            provider_id: Provider identifier attempting to claim winner status.
            model_id: Optional model identifier.

        Returns:
            True if this provider successfully claimed winner status; False if another provider won first.
        """
        now = datetime.now(UTC)
        stmt = (
            update(AIRequestModel)
            .where(
                AIRequestModel.request_id == request_id,
                AIRequestModel.winner_provider.is_(None),
            )
            .values(
                winner_provider=provider_id,
                winner_claimed_at=now,
                updated_at=now,
            )
        )
        res = session.execute(stmt)
        session.flush()

        if res.rowcount == 1:
            logger.info(
                "Hedged execution winner claimed successfully for request '%s' by provider '%s'.",
                request_id,
                provider_id,
            )
            return True

        logger.info(
            "Hedged execution claim rejected for request '%s' by provider '%s' (winner already claimed).",
            request_id,
            provider_id,
        )
        return False
