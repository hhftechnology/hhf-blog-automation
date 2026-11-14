"""Probe each configured AI model without using the briefing cache."""
from __future__ import annotations

import logging

from .ai import AIWriter, TIERS, print_calls


def main() -> int:
    logging.getLogger("httpx").setLevel(logging.WARNING)
    writer = AIWriter(daily=True)
    if not writer.active:
        print("No configured AI providers are available.")
        writer.client.close()
        return 1
    failed = False
    try:
        for tier in TIERS:
            for provider, model in writer.candidates(tier):
                result = writer.try_model(provider, model, tier, "Return only OK.", "Reply OK.", 20)
                failed |= not bool(result)
    except KeyboardInterrupt:
        return 130
    finally:
        writer.client.close()
    print_calls(writer.calls)
    print(f"Total: {writer.neurons:.3f} neurons")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
