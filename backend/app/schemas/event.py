
from datetime import datetime
from typing import Any, Optional, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class SecurityEvent(BaseModel):
    """
    Common normalized security event representation.

    Supports:
    - SIEM authentication and security logs
    - Network connection telemetry
    - Endpoint security events
    - Public research datasets
    - Controlled attack scenarios

    Missing source-specific fields remain optional.
    """

    model_config = ConfigDict(
        extra="allow",
        str_strip_whitespace=True,
    )

    # --------------------------------------------------
    # Event identity
    # --------------------------------------------------

    event_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique normalized event identifier",
    )

    event_type: str = Field(
        description="Normalized event type",
    )

    event_category: Optional[str] = Field(
        default=None,
        description="Category such as authentication, network or malware",
    )

    # --------------------------------------------------
    # Event timestamp
    # --------------------------------------------------

    timestamp: datetime = Field(
    description="Original event occurrence timestamp",
    )

    timestamp_timezone_status: Literal[
    "UTC",
    "OFFSET_AWARE",
    "NAIVE_UNKNOWN",
    ] = Field(
    default="NAIVE_UNKNOWN",
    description=(
        "Timezone status of the original timestamp. "
        "NAIVE_UNKNOWN means the source timezone is not established."
    ),
)

    # --------------------------------------------------
    # Source and destination
    # --------------------------------------------------

    source_ip: Optional[str] = None
    source_port: Optional[int] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    # --------------------------------------------------
    # Local and remote network endpoints
    # --------------------------------------------------

    local_ip: Optional[str] = None
    local_port: Optional[int] = None

    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None

    network_protocol: Optional[str] = None
    connection_status: Optional[str] = None

    # --------------------------------------------------
    # Authentication and user information
    # --------------------------------------------------

    username: Optional[str] = None
    action: Optional[str] = None

    # --------------------------------------------------
    # Endpoint information
    # --------------------------------------------------

    hostname: Optional[str] = None
    process_id: Optional[int] = None
    process_name: Optional[str] = None

    # --------------------------------------------------
    # Classification and research labels
    # --------------------------------------------------

    severity: Optional[str] = None

    labels: list[str] = Field(
        default_factory=list,
    )

    ground_truth_label: Optional[str] = Field(
        default=None,
        description="Verified research label, not a model prediction",
    )

    scenario_id: Optional[str] = Field(
        default=None,
        description="Controlled experiment scenario identifier",
    )

    # --------------------------------------------------
    # Data provenance
    # --------------------------------------------------

    source_system: str = Field(
        default="unknown",
        description="Originating telemetry system or dataset",
    )

    source_index: Optional[str] = None
    source_document_id: Optional[str] = None

    # --------------------------------------------------
    # Original event preservation
    # --------------------------------------------------

    raw_event: Optional[dict[str, Any]] = Field(
        default=None,
        description="Original unmodified source event",
    )
