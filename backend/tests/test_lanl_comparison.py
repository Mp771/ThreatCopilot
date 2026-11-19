
from app.services.ingestion.lanl_comparison import (
    has_nearby_reference_timestamp,
    dataset_hour,
    dataset_day,
    is_temporally_separated,
    has_prior_positive_contamination,
    deterministic_sample,
    is_candidate_eligible,
    is_qualifying_lanl_event,
    relaxed_profile_key,
    exact_hour_profile_key,
    PRIMARY_POLICY,
    STRICT_POLICY,
    TIMESTAMP_ONLY_POLICY,
    candidate_policy_rejection_reasons,
)
from extract_lanl_comparison import CandidateCeilingAudit, percentage


def make_audit_fields(
    timestamp,
    source="C1",
    auth_type="NTLM",
    logon_type="Network",
    orientation="LogOn",
    result="Success",
):
    return [
        str(timestamp),
        "U1",
        "DOM1",
        source,
        "C_DEST",
        auth_type,
        logon_type,
        orientation,
        result,
    ]

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

def test_untracked_only_candidate_is_eligible():
    assert is_candidate_eligible(
        prior_reasons=[],
        simultaneous_reasons=[],
        untracked_reasons=["source_user", "destination_computer"],
    )


def test_contaminated_candidate_is_rejected_even_if_untracked():
    assert not is_candidate_eligible(
        prior_reasons=["source_computer"],
        simultaneous_reasons=[],
        untracked_reasons=["source_user"],
    )

    assert not is_candidate_eligible(
        prior_reasons=[],
        simultaneous_reasons=["destination_computer"],
        untracked_reasons=[],
    )

def test_timestamp_window_rejects_exact_reference_timestamp():
    references = [100, 200, 300]

    assert has_nearby_reference_timestamp(200, references, 5)


def test_timestamp_window_rejects_inclusive_five_second_boundaries():
    references = [100, 200, 300]

    assert has_nearby_reference_timestamp(195, references, 5)
    assert has_nearby_reference_timestamp(205, references, 5)


def test_timestamp_window_allows_candidates_outside_five_seconds():
    references = [100, 200, 300]

    assert not has_nearby_reference_timestamp(194, references, 5)
    assert not has_nearby_reference_timestamp(206, references, 5)


def test_timestamp_window_handles_multiple_reference_timestamps():
    references = [100, 200, 300]

    assert has_nearby_reference_timestamp(295, references, 5)
    assert not has_nearby_reference_timestamp(250, references, 5)


def test_timestamp_window_handles_duplicate_reference_timestamps():
    references = [100, 100, 200, 200, 300]

    assert has_nearby_reference_timestamp(105, references, 5)
    assert not has_nearby_reference_timestamp(110, references, 5)

def test_primary_policy_uses_timestamp_and_same_timestamp_overlap():
    reasons = candidate_policy_rejection_reasons(
        policy=PRIMARY_POLICY,
        timestamp=105,
        reference_timestamps=[100, 200],
        prior_reasons=["source_user"],
        simultaneous_reasons=["source_computer"],
    )

    assert reasons == [
        "nearby_redteam_timestamp",
        "same_timestamp_source_computer",
    ]


def test_strict_policy_uses_prior_and_same_timestamp_overlap():
    reasons = candidate_policy_rejection_reasons(
        policy=STRICT_POLICY,
        timestamp=150,
        reference_timestamps=[150],
        prior_reasons=["source_user", "destination_computer"],
        simultaneous_reasons=["source_computer"],
    )

    assert reasons == [
        "prior_positive_source_user",
        "prior_positive_destination_computer",
        "same_timestamp_source_computer",
    ]


def test_timestamp_only_policy_ignores_entity_overlap():
    reasons = candidate_policy_rejection_reasons(
        policy=TIMESTAMP_ONLY_POLICY,
        timestamp=150,
        reference_timestamps=[150],
        prior_reasons=["source_user"],
        simultaneous_reasons=["source_computer"],
    )

    assert reasons == ["nearby_redteam_timestamp"]


def test_timestamp_only_policy_accepts_candidate_outside_window():
    reasons = candidate_policy_rejection_reasons(
        policy=TIMESTAMP_ONLY_POLICY,
        timestamp=150,
        reference_timestamps=[100, 200],
        prior_reasons=["source_user"],
        simultaneous_reasons=["source_computer"],
    )

    assert reasons == []


def test_primary_policy_ignores_prior_history():
    reasons = candidate_policy_rejection_reasons(
        policy=PRIMARY_POLICY,
        timestamp=150,
        reference_timestamps=[100, 200],
        prior_reasons=["source_user"],
        simultaneous_reasons=[],
    )

    assert reasons == []


def test_unknown_comparison_policy_is_rejected():
    import pytest

    with pytest.raises(ValueError, match="Unknown comparison policy"):
        candidate_policy_rejection_reasons(
            policy="unknown",
            timestamp=150,
            reference_timestamps=[],
            prior_reasons=[],
            simultaneous_reasons=[],
        )


def test_ntlm_network_logon_success_qualifies():
    fields = make_audit_fields(3600)
    assert is_qualifying_lanl_event(fields, {"C1"})


def test_ntlm_network_logon_fail_qualifies():
    fields = make_audit_fields(3600, result="Fail")
    assert is_qualifying_lanl_event(fields, {"C1"})


def test_different_authentication_type_does_not_qualify():
    fields = make_audit_fields(3600, auth_type="Kerberos")
    assert not is_qualifying_lanl_event(fields, {"C1"})


def test_different_logon_type_does_not_qualify():
    fields = make_audit_fields(3600, logon_type="Interactive")
    assert not is_qualifying_lanl_event(fields, {"C1"})


def test_different_orientation_does_not_qualify():
    fields = make_audit_fields(3600, orientation="LogOff")
    assert not is_qualifying_lanl_event(fields, {"C1"})


def test_source_computer_outside_four_host_set_does_not_qualify():
    fields = make_audit_fields(3600, source="C_OTHER")
    assert not is_qualifying_lanl_event(fields, {"C1", "C2", "C3", "C4"})


def test_relaxed_profile_matches_across_hours():
    first = make_audit_fields(3600)
    second = make_audit_fields(7200)

    assert relaxed_profile_key(first, 3600) == relaxed_profile_key(
        second,
        7200,
    )


def test_exact_hour_profile_differs_across_hours():
    first = make_audit_fields(3600)
    second = make_audit_fields(7200)

    assert exact_hour_profile_key(first, 3600) != exact_hour_profile_key(
        second,
        7200,
    )


def test_labelled_line_is_excluded_from_unlabelled_but_in_raw_counts():
    audit = CandidateCeilingAudit(
        {"C1"},
        known_relaxed_strata={
            ("C1", 0, "NTLM", "Network", "LogOn", "Success"),
        },
        known_exact_strata={
            ("C1", 0, 1, "NTLM", "Network", "LogOn", "Success"),
        },
        labelled_line_count=1,
    )
    audit.record(1, make_audit_fields(3600), {1: {"label": "positive"}})

    report = audit.report()
    assert report["raw_population"]["total"] == 1
    assert report["unlabelled_population"]["total"] == 0


def test_zero_denominator_percentages_are_unavailable():
    assert percentage(0, 0) is None
    assert percentage(5, 0) is None


def test_source_computer_and_day_counts_accumulate():
    audit = CandidateCeilingAudit(
        {"C1", "C2"},
        known_relaxed_strata=set(),
        known_exact_strata=set(),
    )
    audit.record(1, make_audit_fields(3600, source="C1"), {})
    audit.record(2, make_audit_fields(7200, source="C1"), {})
    audit.record(3, make_audit_fields(90000, source="C2"), {})

    report = audit.report()
    raw = report["raw_population"]
    assert raw["total"] == 3
    assert raw["by_source_computer"] == {"C1": 2, "C2": 1}
    assert raw["by_source_computer_and_day"]["C1"]["0"] == 2
    assert raw["by_source_computer_and_day"]["C2"]["1"] == 1


def test_exact_and_relaxed_population_comparison():
    relaxed_key = ("C1", 0, "NTLM", "Network", "LogOn", "Success")
    exact_key = ("C1", 0, 1, "NTLM", "Network", "LogOn", "Success")
    audit = CandidateCeilingAudit(
        {"C1"},
        known_relaxed_strata={relaxed_key},
        known_exact_strata={exact_key},
    )

    audit.record(1, make_audit_fields(3600), {})
    audit.record(2, make_audit_fields(7200), {})

    report = audit.report()["unlabelled_population"]
    assert report["total"] == 2
    assert report["same_host_day_profile_matches"] == 2
    assert report["exact_hour_strata_matches"] == 1
    assert report["additional_matches_without_hour_restriction"] == 1
    assert report["exact_hour_match_percentage"] == 50.0
    assert report["population_lost_to_hour_restriction_percentage"] == 50.0