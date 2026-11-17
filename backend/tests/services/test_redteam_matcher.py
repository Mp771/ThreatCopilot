import pytest

from app.services.ingestion.redteam_matcher import (
    parse_redteam_record,
    parse_auth_record,
    build_redteam_key_set,
    classify_auth_record,
)


def test_parse_redteam_record():
    line = "150885,U620@DOM1,C17693,C1003"

    result = parse_redteam_record(line)

    assert result == (
        "150885",
        "U620@DOM1",
        "C17693",
        "C1003",
    )


def test_parse_auth_record():
    line = (
        "150885,U620@DOM1,U620@DOM1,"
        "C17693,C1003,NTLM,Network,LogOn,Success"
    )

    result = parse_auth_record(line)

    assert result == (
        "150885",
        "U620@DOM1",
        "C17693",
        "C1003",
    )


def test_duplicate_redteam_records_are_deduplicated():
    records = [
        "150885,U620@DOM1,C17693,C1003",
        "150885,U620@DOM1,C17693,C1003",
    ]

    result = build_redteam_key_set(records)

    assert len(result) == 1


def test_matching_auth_record_is_redteam_activity():
    redteam_keys = {
        ("150885", "U620@DOM1", "C17693", "C1003")
    }

    auth_record = (
        "150885,U620@DOM1,U620@DOM1,"
        "C17693,C1003,NTLM,Network,LogOn,Success"
    )

    result = classify_auth_record(auth_record, redteam_keys)

    assert result == "redteam_activity"


def test_unmatched_auth_record_remains_unlabelled():
    redteam_keys = {
        ("150885", "U620@DOM1", "C17693", "C1003")
    }

    auth_record = (
        "150886,U620@DOM1,U620@DOM1,"
        "C17693,C1003,NTLM,Network,LogOn,Success"
    )

    result = classify_auth_record(auth_record, redteam_keys)

    assert result == "unlabelled"


def test_invalid_redteam_record_raises_error():
    with pytest.raises(ValueError):
        parse_redteam_record("150885,U620@DOM1,C17693")


def test_invalid_auth_record_raises_error():
    with pytest.raises(ValueError):
        parse_auth_record("150885,U620@DOM1,C17693,C1003")


def test_empty_redteam_records_produce_empty_set():
    result = build_redteam_key_set([])

    assert result == set()