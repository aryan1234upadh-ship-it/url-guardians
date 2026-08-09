import streamlit as st
import requests
import os
from streamlit_google_auth import Authenticate

BACKEND_URL = "https://url-guardians-1.onrender.com"

st.set_page_config(page_title="URL Guardians", page_icon="🛡️", layout="wide")

# ── Google Auth Setup ─────────────────────────────────────
authenticator = Authenticate(
    secret_credentials_path=None,
    cookie_name="url_guardians_cookie",
    cookie_key=os.getenv("SECRET_KEY", "url-guardians-secret"),
    redirect_uri=os.getenv("REDIRECT_URI", "http://localhost:8501"),
    google_client_id=os.getenv("GOOGLE_CLIENT_ID"),
    google_client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
)

# ── Session State ─────────────────────────────────────────
if "connected" not in st.session_state:
    st.session_state.connected = False
if "user_info" not in st.session_state:
    st.session_state.user_info = {}

# ── Login Page ────────────────────────────────────────────
def show_auth_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align:center'>🛡️ URL Guardians</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center'>AI-Powered Security Auditor | MCKV Institute of Engineering</p>", unsafe_allow_html=True)
        st.markdown("---")
        st.markdown("<h3 style='text-align:center'>Sign in to continue</h3>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        # Google Login Button
        authenticator.check_authentification()
        authenticator.login()

# ── Main App ──────────────────────────────────────────────
def show_main_app():
    user_name = st.session_state.get("user_info", {}).get("name", "User")
    user_email = st.session_state.get("user_info", {}).get("email", "")
    user_picture = st.session_state.get("user_info", {}).get("picture", "")

    col1, col2 = st.columns([4, 1])
    with col1:
        st.title("🛡️ URL Guardians")
        if user_picture:
            st.markdown(f"Welcome, **{user_name}** ({user_email})")
    with col2:
        if st.button("🚪 Logout"):
            authenticator.logout()
            st.rerun()

    st.markdown("---")

    st.sidebar.title("⚙️ Settings")
    st.sidebar.markdown(f"👤 **{user_name}**")
    st.sidebar.markdown(f"📧 {user_email}")
    st.sidebar.markdown("---")
    mode = st.sidebar.selectbox(
        "Scan Mode",
        ["normal", "deep"],
        format_func=lambda x: "🔍 Normal Scan" if x == "normal" else "🔬 Deep Scan"
    )

    st.markdown("### 🔍 Enter URL to Analyze")
    url = st.text_input("URL", placeholder="https://example.com")

    col1, col2 = st.columns([1, 1])
    analyze_btn = col1.button("🚀 Analyze URL", use_container_width=True, type="primary")
    pdf_btn = col2.button("📄 Export PDF", use_container_width=True)

    if analyze_btn:
        if not url:
            st.warning("⚠️ Please enter a URL!")
        elif not url.startswith("http"):
            st.error("❌ URL must start with http:// or https://")
        else:
            with st.spinner("🤖 AI Agents analyzing..."):
                try:
                    res = requests.post(
                        f"{BACKEND_URL}/analyze",
                        json={"url": url, "mode": mode},
                        timeout=60
                    )
                    data = res.json()
                    if data.get("status") == "success":
                        st.success("✅ Analysis Complete!")
                        st.markdown("---")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("### 🔎 Agent 1 — URL Classifier")
                            st.json(data["classification"]["output"])
                            st.markdown("### 💉 Agent 3 — Payload Suggester")
                            st.json(data["payloads"]["output"])
                        with col2:
                            st.markdown("### ⚔️ Agent 2 — Attack Planner")
                            st.json(data["attack_plan"]["output"])
                            st.markdown("### 📝 Agent 4 — Report Writer")
                            st.json(data["report"]["output"])
                    else:
                        st.error(f"❌ Error: {data}")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

    if pdf_btn:
        if not url:
            st.warning("⚠️ Please enter a URL!")
        else:
            with st.spinner("📄 Generating PDF..."):
                try:
                    res = requests.post(
                        f"{BACKEND_URL}/export-pdf",
                        json={"url": url, "mode": mode},
                        timeout=120
                    )
                    if res.status_code == 200:
                        st.success("✅ PDF Ready!")
                        st.download_button(
                            label="⬇️ Download PDF Report",
                            data=res.content,
                            file_name="url_guardians_report.pdf",
                            mime="application/pdf",
                            use_container_width=True
                        )
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")

# ── Router ────────────────────────────────────────────────
if st.session_state.get("connected"):
    show_main_app()
else:
    show_auth_page()