import gzip

from extract_lanl_comparison import (
    discover_candidate_entities,
    matching_key,
)


def make_auth_record(
    timestamp,
    user,
    source,
    destination,
    auth_type="LogOn",
    logon_type="Interactive",
    orientation="LogOn",
    result="Success",
):
    return ",".join([
        str(timestamp),
        user,
        "domain",
        source,
        destination,
        auth_type,
        logon_type,
        orientation,
        result,
    ])


def test_discovery_collects_only_unlabelled_matching_entities(tmp_path):
    auth_file = tmp_path / "auth.txt.gz"

    labelled_record = make_auth_record(
        150885, "U_LABELLED", "C1", "C_LABELLED"
    )
    candidate_record = make_auth_record(
        150886, "U_CANDIDATE", "C1", "C_CANDIDATE"
    )
    unrelated_record = make_auth_record(
        150887,
        "U_OTHER",
        "C_OTHER",
        "C_OTHER_DEST",
        auth_type="OtherAuth",
    )

    with gzip.open(auth_file, "wt", encoding="utf-8") as file:
        file.write(labelled_record + "\n")
        file.write(candidate_record + "\n")
        file.write(unrelated_record + "\n")

    candidate_row = {
        "timestamp": "150886",
        "source_computer": "C1",
        "source_user": "U_CANDIDATE",
        "destination_computer": "C_CANDIDATE",
        "authentication_type": "LogOn",
        "logon_type": "Interactive",
        "orientation": "LogOn",
        "result": "Success",
    }

    candidate_keys = {matching_key(candidate_row)}

    users, sources, destinations = discover_candidate_entities(
        auth_file,
        labelled_by_line={1: {"label": "positive"}},
        candidate_keys=candidate_keys,
    )

    assert users == {"U_CANDIDATE"}
    assert sources == {"C1"}
    assert destinations == {"C_CANDIDATE"}