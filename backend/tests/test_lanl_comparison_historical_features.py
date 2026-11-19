
from extract_lanl_features import HistoricalFeatures


def make_event(timestamp, user, source, destination, result="Success"):
    return [
        str(timestamp),
        user,
        "DOMAIN",
        source,
        destination,
        "LogOn",
        "Interactive",
        "LogOn",
        result,
    ]


def test_candidate_entities_receive_prior_historical_features():
    engine = HistoricalFeatures()

    # These entities are absent from the original positive-label sets.
    candidate_user = "U_CANDIDATE"
    candidate_source = "C_CANDIDATE"
    candidate_destination = "C_DESTINATION"

    tracked_users = {candidate_user, "U_OTHER"}
    tracked_sources = {candidate_source, "C_OTHER"}
    tracked_destinations = {candidate_destination, "C_PRIOR"}

    # Earlier events provide historical context for the candidate.
    earlier_events = [
        make_event(100, candidate_user, candidate_source, "C_PRIOR"),
        make_event(100, "U_OTHER", "C_OTHER", candidate_destination),
    ]

    engine.update(
        earlier_events,
        100,
        tracked_users,
        tracked_sources,
        tracked_destinations,
    )

    # This event shares the candidate timestamp.
    # It must not influence the candidate's calculated features.
    same_timestamp_event = make_event(
        200,
        candidate_user,
        candidate_source,
        candidate_destination,
    )

    candidate = make_event(
        200,
        candidate_user,
        candidate_source,
        candidate_destination,
    )

    features = engine.calculate(candidate, 200)

    # User history comes from the earlier event only.
    assert features["user_auth_count_1h"] == 1
    assert features["user_unique_destinations_1h"] == 1

    # Destination history comes from the earlier event only.
    assert features["destination_auth_count_1h"] == 1
    assert features["destination_unique_source_users_1h"] == 1

    # Same-timestamp events are added only after feature calculation.
    engine.update(
        [same_timestamp_event, candidate],
        200,
        tracked_users,
        tracked_sources,
        tracked_destinations,
    )

    updated_features = engine.calculate(candidate, 200)

    assert updated_features["user_auth_count_1h"] == 3
    assert updated_features["destination_auth_count_1h"] == 3
