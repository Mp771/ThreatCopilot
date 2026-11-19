
import random
from bisect import bisect_left, bisect_right
from collections.abc import Sequence
from typing import Any

PRIMARY_POLICY = "primary"
STRICT_POLICY = "strict"
TIMESTAMP_ONLY_POLICY = "timestamp_only"

COMPARISON_POLICIES = (
    PRIMARY_POLICY,
    STRICT_POLICY,
    TIMESTAMP_ONLY_POLICY,
)

def dataset_day(timestamp: int) -> int:
    return int(timestamp) // 86400


def dataset_hour(timestamp: int) -> int:
    return (int(timestamp) // 3600) % 24


def is_qualifying_lanl_event(fields, positive_source_computers):
    if len(fields) != 9:
        return False

    return (
        fields[3] in positive_source_computers
        and fields[5] == "NTLM"
        and fields[6] == "Network"
        and fields[7] == "LogOn"
        and fields[8] in {"Success", "Fail"}
    )


def relaxed_profile_key(fields, timestamp):
    return (
        fields[3],
        dataset_day(timestamp),
        fields[5],
        fields[6],
        fields[7],
        fields[8],
    )


def exact_hour_profile_key(fields, timestamp):
    return (
        fields[3],
        dataset_day(timestamp),
        dataset_hour(timestamp),
        fields[5],
        fields[6],
        fields[7],
        fields[8],
    )

def has_nearby_reference_timestamp(
    timestamp: int,
    reference_timestamps: Sequence[int],
    window_seconds: int = 5,
) -> bool:
    """
    Return True when a candidate timestamp is within the inclusive
    +/- window around any red-team reference timestamp.

    reference_timestamps must be sorted in ascending order.
    """
    timestamp = int(timestamp)
    lower_bound = timestamp - window_seconds
    upper_bound = timestamp + window_seconds

    index = bisect_left(reference_timestamps, lower_bound)

    return (
        index < len(reference_timestamps)
        and reference_timestamps[index] <= upper_bound
    )

def candidate_policy_rejection_reasons(
    policy,
    timestamp,
    reference_timestamps,
    prior_reasons,
    simultaneous_reasons,
    timestamp_window_seconds=5,
):
    """
    Evaluate candidate eligibility under one comparison policy.

    Primary:
        +/- timestamp window and same-timestamp entity overlap.

    Strict:
        Prior-positive overlap and same-timestamp entity overlap.

    Timestamp-only:
        +/- timestamp window only.
    """
    if policy not in COMPARISON_POLICIES:
        raise ValueError(f"Unknown comparison policy: {policy}")

    reasons = []

    if policy in (PRIMARY_POLICY, TIMESTAMP_ONLY_POLICY):
        if has_nearby_reference_timestamp(
            timestamp,
            reference_timestamps,
            timestamp_window_seconds,
        ):
            reasons.append("nearby_redteam_timestamp")

    if policy == STRICT_POLICY:
        reasons.extend(
            f"prior_positive_{reason}"
            for reason in prior_reasons
        )

    if policy in (PRIMARY_POLICY, STRICT_POLICY):
        reasons.extend(
            f"same_timestamp_{reason}"
            for reason in simultaneous_reasons
        )

    return reasons

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

def is_candidate_eligible(
    prior_reasons: list[str],
    simultaneous_reasons: list[str],
    untracked_reasons: list[str],
) -> bool:
    """
    Reject contaminated candidates.

    Untracked entities are diagnostic only because the feature engine
    now tracks entities discovered during candidate discovery.
    """
    return not prior_reasons and not simultaneous_reasons

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
