
import random
from bisect import bisect_left
from collections.abc import Sequence
from typing import Any


def dataset_day(timestamp: int) -> int:
    return int(timestamp) // 86400


def dataset_hour(timestamp: int) -> int:
    return (int(timestamp) // 3600) % 24

def prior_positive_contamination_reasons(
    candidate: dict[str, Any],
    positives: dict[str, dict[str, list[int]]],
    window_seconds: int = 3600,
) -> list[str]:
    timestamp = int(candidate["timestamp"])
    lower_bound = timestamp - window_seconds

    entity_fields = (
        ("source_user", "source_users"),
        ("source_computer", "source_computers"),
        ("destination_computer", "destination_computers"),
    )

    reasons = []

    for candidate_field, positive_group in entity_fields:
        entity = candidate.get(candidate_field)

        if entity is None:
            continue

        timestamps = positives.get(positive_group, {}).get(entity, [])
        index = bisect_left(timestamps, lower_bound)

        if index < len(timestamps) and timestamps[index] < timestamp:
            reasons.append(candidate_field)

    return reasons

def is_temporally_separated(
    train_max_timestamp: int,
    test_min_timestamp: int,
) -> bool:
    return train_max_timestamp < test_min_timestamp


def has_prior_positive_contamination(
    candidate: dict[str, Any],
    positives: dict[str, dict[str, list[int]]],
    window_seconds: int = 3600,
) -> bool:
    return bool(
        prior_positive_contamination_reasons(
            candidate,
            positives,
            window_seconds,
        )
    )

    for candidate_field, positive_group in entity_fields:
        entity = candidate.get(candidate_field)

        if entity is None:
            continue

        timestamps = positives.get(positive_group, {}).get(entity, [])
        index = bisect_left(timestamps, lower_bound)

        if index < len(timestamps) and timestamps[index] < timestamp:
            return True

    return False


def deterministic_sample(
    records: Sequence[Any],
    sample_size: int,
    seed: int = 42,
) -> list[Any]:
    if sample_size < 0:
        raise ValueError("sample_size cannot be negative")

    count = min(sample_size, len(records))
    rng = random.Random(seed)
    indices = sorted(rng.sample(range(len(records)), count))

    return [records[index] for index in indices]
