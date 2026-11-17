from typing import Iterable


RedTeamKey = tuple[str, str, str, str]


def parse_redteam_record(line: str) -> RedTeamKey:
    """
    Parse one four-column LANL red-team record.

    Format:
    time, user, source_computer, destination_computer
    """
    fields = line.strip().split(",")

    if len(fields) != 4:
        raise ValueError(
            f"Expected 4 red-team fields, received {len(fields)}"
        )

    return tuple(fields)


def parse_auth_record(line: str) -> RedTeamKey:
    """
    Extract the red-team matching key from a nine-column
    LANL authentication record.

    Matching fields:
    time, source_user, source_computer, destination_computer
    """
    fields = line.strip().split(",")

    if len(fields) != 9:
        raise ValueError(
            f"Expected 9 authentication fields, received {len(fields)}"
        )

    return (
        fields[0],
        fields[1],
        fields[3],
        fields[4],
    )


def build_redteam_key_set(
    records: Iterable[str],
) -> set[RedTeamKey]:
    """
    Build a unique set of red-team matching keys.
    Duplicate reference records are naturally deduplicated.
    """
    keys = set()

    for record in records:
        if record.strip():
            keys.add(parse_redteam_record(record))

    return keys


def classify_auth_record(
    line: str,
    redteam_keys: set[RedTeamKey],
) -> str:
    """
    Match an authentication record against known red-team keys.

    Unmatched records remain unlabelled. They are not assumed
    to be benign.
    """
    key = parse_auth_record(line)

    if key in redteam_keys:
        return "redteam_activity"

    return "unlabelled"