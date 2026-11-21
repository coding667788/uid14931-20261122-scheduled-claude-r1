"""mapping_guard -- virtual device remapping safety auditor (pure logic, no hardware).

Subcommands:
    apply    -- process a batch of logical events against an SQLite event log
    inspect  -- audit outstanding invalidation evidence at a given commit
    schedule -- compute a robust maintenance command plan for timed handoffs
"""

__version__ = "1.0.0"

ADDRESS_MAX = 1 << 52
