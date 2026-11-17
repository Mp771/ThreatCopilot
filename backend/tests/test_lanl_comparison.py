
from app.services.ingestion.lanl_comparison import (
    dataset_hour,
    dataset_day,
    is_temporally_separated,
    has_prior_positive_contamination,
    deterministic_sample,
)


def test_dataset_day_and_hour():
    assert dataset_day(150885) == 1
    assert dataset_hour(3600) == 1
    assert dataset_hour(25 * 3600) == 1


def test_train_test_timestamp_separation():
    assert is_temporally_separated(
        train_max_timestamp=1_200_000,
        test_min_timestamp=1_300_000,
    )

    assert not is_temporally_separated(
        train_max_timestamp=1_300_000,
        test_min_timestamp=1_300_000,
    )


def test_prior_positive_contamination():
    positives = {
        "source_users": {"U1": [1000]},
        "source_computers": {"C1": [1000]},
        "destination_computers": {"D1": [1000]},
    }

    candidate = {
        "timestamp": 1500,
        "source_user": "U1",
        "source_computer": "C9",
        "destination_computer": "D9",
    }

    assert has_prior_positive_contamination(candidate, positives, 3600)

    candidate["source_user"] = "U9"
    assert not has_prior_positive_contamination(candidate, positives, 3600)


def test_deterministic_sampling():
    records = list(range(100))

    first = deterministic_sample(records, 10, seed=42)
    second = deterministic_sample(records, 10, seed=42)

    assert first == second
    assert len(first) == 10
    assert len(set(first)) == 10


def test_sampling_does_not_exceed_population():
    records = list(range(5))

    sample = deterministic_sample(records, 10, seed=42)

    assert len(sample) == 5
