
import json
from pathlib import Path
from dashboard_utils import load_events, normalize_event
import streamlit as st

AUDIT_FILE = Path(__file__).resolve().parent / "audit.jsonl"

st.set_page_config(
    page_title="AgentShield Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AgentShield Security Dashboard")
st.caption("Security monitoring for authenticated AI agents")

@st.fragment(run_every="5s")
def security_dashboard():
    events = load_events()

    normalized_events = [
        normalize_event(event)
        for event in events
    ]
security_dashboard()

total_events = len(events)

allowed_events = sum(
    event.get("allowed") is True
    for event in events
)

denied_events = sum(
    event.get("allowed") is False
    for event in events
)

injection_alerts = sum(
    event.get("event_type") == "prompt_injection"
    for event in events
)


col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Security Events",
    total_events
)

col2.metric(
    "Allowed Actions",
    allowed_events
)

col3.metric(
    "Denied Actions",
    denied_events
)

col4.metric(
    "Prompt Injection Alerts",
    injection_alerts
)


st.subheader("Security Event Filters")

col_agent, col_type, col_status = st.columns(3)

agent_options = sorted({
    event["agent_id"]
    for event in normalized_events
})

type_options = sorted({
    event["event_type"]
    for event in normalized_events
})

status_options = sorted({
    event["status"]
    for event in normalized_events
})

with col_agent:
    selected_agent = st.selectbox(
        "Select Agent",
        ["All Agents"] + agent_options,
    )

with col_type:
    selected_type = st.selectbox(
        "Event Type",
        ["All Types"] + type_options,
    )

with col_status:
    selected_status = st.selectbox(
        "Decision Status",
        ["All Statuses"] + status_options,
    )

filtered_events = [
    event
    for event in normalized_events
    if (
        (selected_agent == "All Agents"
         or event["agent_id"] == selected_agent)
        and
        (selected_type == "All Types"
         or event["event_type"] == selected_type)
        and
        (selected_status == "All Statuses"
         or event["status"] == selected_status)
    )
]

st.caption(f"Showing {len(filtered_events)} matching events")

if filtered_events:
    st.dataframe(
        list(reversed(filtered_events[-100:])),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.info("No events match the selected filters.")


st.subheader("Security Activity Analytics")

chart_left, chart_right = st.columns(2)

with chart_left:
    st.markdown("**Authorization Decisions**")

    decision_counts = {
        "Allowed": allowed_events,
        "Denied": denied_events,
    }

    st.bar_chart(
        decision_counts,
        x_label="Decision",
        y_label="Number of Events",
    )

with chart_right:
    st.markdown("**Activity by Agent**")

    agent_counts = {}

    for event in normalized_events:
        agent = event["agent_id"]
        agent_counts[agent] = agent_counts.get(agent, 0) + 1

    st.bar_chart(
        agent_counts,
        x_label="Agent",
        y_label="Number of Events",
    )
