import hmac
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

import streamlit as st

# Logger configuration
logger = logging.getLogger(__name__)

# Project configuration
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

st.set_page_config(
    page_title="ATT&CK Intelligence",
    page_icon="🛡️",
    layout="wide",
)

# Dashboard styling
st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(
            180deg,
            #081120 0%,
            #0B1220 100%
        );
    }

    .block-container {
        max-width: 1200px;
        padding-top: 2rem;
        padding-bottom: 3rem;
    }

    div[data-testid="stMetric"] {
        background-color: #111D30;
        border: 1px solid #243B61;
        border-radius: 14px;
        padding: 20px;
    }

    div[data-testid="stMetricValue"] {
        color: #60A5FA;
    }

    button[kind="primary"] {
        background: linear-gradient(
            90deg,
            #2563EB,
            #1D4ED8
        );
        color: white;
        border: 1px solid #3B82F6;
        border-radius: 10px;
        font-weight: 600;
    }

    button[kind="primary"]:hover {
        background: #1E40AF;
        border-color: #60A5FA;
        color: white;
    }

    textarea {
        background-color: #111827 !important;
        border-radius: 12px !important;
    }

    div[data-testid="stVerticalBlockBorderWrapper"] {
        border-radius: 14px;
    }

    a {
        color: #60A5FA;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Optional access protection
app_password = os.getenv("APP_PASSWORD")

if app_password:
    entered_password = st.text_input(
        "Application password",
        type="password",
    )

    if not hmac.compare_digest(
        entered_password,
        app_password,
    ):
        st.info("Enter the application password to continue.")
        st.stop()

# Session state
if "analysis" not in st.session_state:
    st.session_state.analysis = None

# Header
st.title("🛡️ ATT&CK Intelligence")
st.caption("Threat Analysis Workspace · Powered by MITRE ATT&CK")

st.divider()

# Dashboard
col1, col2, col3 = st.columns(3)

with col1:
    st.metric("MITRE Techniques", "706")

with col2:
    st.metric("Knowledge Base", "Enterprise ATT&CK")

with col3:
    st.metric("Retrieval", "Top 3")

st.divider()

# Threat input
st.subheader("Analyze suspicious activity")

st.write(
    "Describe the observed behaviour to identify relevant "
    "MITRE ATT&CK techniques."
)

with st.form("threat_analysis_form"):
    query = st.text_area(
        "Threat description",
        placeholder=(
            "Example: A suspicious process executes encoded "
            "PowerShell commands on a Windows workstation."
        ),
        height=160,
    )

    analyze = st.form_submit_button(
        "🔎 Analyze Threat",
        type="primary",
    )

# Run the RAG pipeline only when the form is submitted
if analyze:
    if not query.strip():
        st.warning("Please enter a threat description.")

    else:
        st.session_state.analysis = None

        with st.spinner("Analyzing suspicious activity..."):
            try:
                from backend.rag.rag_chain import analyze_query

                result = analyze_query(query.strip())

                if not isinstance(result, dict):
                    raise TypeError("Invalid analysis response")

                if result.get("status") not in (
                    "supported",
                    "insufficient_evidence",
                ):
                    raise ValueError("Invalid analysis status")

                if not isinstance(result.get("techniques"), list):
                    raise TypeError("Invalid techniques")

                if not isinstance(result.get("answer"), str):
                    raise TypeError("Invalid explanation")

                st.session_state.analysis = result

            except Exception:
                logger.exception("Threat analysis failed")
                st.error(
                    "The analysis could not be completed. "
                    "Please try again later."
                )

# Analysis results
if st.session_state.analysis is not None:
    data = st.session_state.analysis
    techniques = data["techniques"]
    status = data["status"]

    st.divider()
    st.subheader("Threat Analysis Results")

    if status == "insufficient_evidence":
        with st.container(border=True):
            st.warning("Insufficient Evidence")

            st.markdown("## No technique assigned")

            st.write(
                "The observed activity does not provide enough "
                "evidence to reliably identify a MITRE ATT&CK technique."
            )

            st.caption(
                "Provide additional process, command, network, "
                "or system activity details for a more accurate analysis."
            )

    elif status == "supported" and techniques:
        st.success("Analysis completed")

        primary = techniques[0]

        # Main supported technique
        with st.container(border=True):
            st.caption("TOP SUPPORTED TECHNIQUE")

            st.markdown(f"## :blue[{primary['id']}]")
            st.subheader(primary["name"])

            col1, col2 = st.columns(2)

            with col1:
                st.caption("TACTICS")
                st.write(primary.get("tactics") or "Not specified")

            with col2:
                st.caption("PLATFORMS")
                st.write(primary.get("platforms") or "Not specified")

            st.link_button(
                "View on MITRE ATT&CK ↗",
                primary["url"],
            )

        # Additional supported techniques
        if len(techniques) > 1:
            st.subheader("Other Supported Techniques")

            cols = st.columns(2)

            for index, technique in enumerate(techniques[1:]):
                with cols[index % 2], st.container(border=True):
                    st.markdown(f"### :blue[{technique['id']}]")

                    st.write(technique["name"])

                    st.link_button(
                        "MITRE Reference ↗",
                        technique["url"],
                    )

    else:
        st.error("The analysis returned inconsistent results.")

    with st.expander("📄 View Detailed Analysis"):
        st.markdown(data["answer"])
