import streamlit as st
import requests
import os

BACKEND_URL = "https://url-guardians-1.onrender.com"

st.set_page_config(page_title="URL Guardians", page_icon="🛡️", layout="wide")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "token" not in st.session_state:
    st.session_state.token = None
if "username" not in st.session_state:
    st.session_state.username = None

def show_auth_page():
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("<h1 style='text-align:center'>🛡️ URL Guardians</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center'>AI-Powered Security Auditor | MCKV Institute of Engineering</p>", unsafe_allow_html=True)
        st.markdown("---")

        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])

        with tab1:
            st.subheader("Welcome Back!")
            username = st.text_input("Username", key="login_user", placeholder="Enter username")
            password = st.text_input("Password", type="password", key="login_pass", placeholder="Enter password")
            if st.button("🔐 Login", use_container_width=True, type="primary"):
                if not username or not password:
                    st.error("❌ Please fill all fields!")
                else:
                    with st.spinner("Logging in..."):
                        try:
                            res = requests.post(
                                f"{BACKEND_URL}/auth/login",
                                json={"username": username, "password": password}
                            )
                            data = res.json()
                            if res.status_code == 200:
                                st.session_state.logged_in = True
                                st.session_state.token = data["token"]
                                st.session_state.username = data["username"]
                                st.session_state.is_admin = data.get("is_admin", False)
                                st.success("✅ Login successful!")
                                st.rerun()
                            else:
                                st.error(f"❌ {data.get('detail', 'Login failed!')}")
                        except Exception:
                            st.error("❌ Backend not running!")

        with tab2:
            st.subheader("Create Account")
            new_username = st.text_input("Username", key="reg_user", placeholder="Choose a username")
            new_email = st.text_input("Email", key="reg_email", placeholder="Enter your email")
            new_password = st.text_input("Password", type="password", key="reg_pass", placeholder="Min 8 characters")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm", placeholder="Repeat password")
            if st.button("📝 Register", use_container_width=True, type="primary"):
                if not new_username or not new_email or not new_password:
                    st.error("❌ Please fill all fields!")
                elif new_password != confirm_password:
                    st.error("❌ Passwords do not match!")
                elif len(new_password) < 8:
                    st.error("❌ Password must be at least 8 characters!")
                else:
                    with st.spinner("Creating account..."):
                        try:
                            res = requests.post(
                                f"{BACKEND_URL}/auth/register",
                                json={"username": new_username, "email": new_email, "password": new_password}
                            )
                            data = res.json()
                            if res.status_code == 200:
                                st.success("✅ Account created! Please login.")
                            else:
                                st.error(f"❌ {data.get('detail', 'Registration failed!')}")
                        except Exception:
                            st.error("❌ Backend not running!")
def show_admin_dashboard():
    st.markdown("## 👑 Admin Dashboard")
    st.markdown("---")

    headers = {"Authorization": f"Bearer {st.session_state.token}"}

    # Stats
    try:
        res = requests.get(f"{BACKEND_URL}/admin/stats", headers=headers)
        stats = res.json()
        col1, col2, col3 = st.columns(3)
        col1.metric("👥 Total Users", stats["total_users"])
        col2.metric("✅ Active Users", stats["active_users"])
        col3.metric("🔍 Total Scans", stats["total_scans"])
    except Exception as e:
        st.error(f"Failed to load stats: {e}")

    st.markdown("---")

    tab1, tab2 = st.tabs(["👥 Users", "🔍 Scan History"])

    with tab1:
        try:
            res = requests.get(f"{BACKEND_URL}/admin/users", headers=headers)
            users = res.json()["users"]
            for user in users:
                col1, col2, col3, col4 = st.columns([2, 2, 2, 1])
                col1.write(f"**{user['username']}**")
                col2.write(user['email'])
                col3.write("🟢 Active" if user['is_active'] else "🔴 Banned")
                if user['username'] != st.session_state.username:
                    if col4.button("🚫 Ban", key=f"ban_{user['username']}"):
                        requests.delete(f"{BACKEND_URL}/admin/users/{user['username']}", headers=headers)
                        st.success(f"Banned {user['username']}")
                        st.rerun()
        except Exception as e:
            st.error(f"Failed to load users: {e}")

    with tab2:
        try:
            res = requests.get(f"{BACKEND_URL}/admin/scans", headers=headers)
            scans = res.json()["scans"]
            if scans:
                for scan in scans:
                    st.write(f"🔗 **{scan['url']}** — Risk: {scan['risk_level']} — {scan['created_at']}")
            else:
                st.info("No scans yet")
        except Exception as e:
            st.error(f"Failed to load scans: {e}")                           

def show_main_app():
    col1, col2 = st.columns([4, 1])
    col1.title("🛡️ URL Guardians")
    col1.caption(f"Welcome, **{st.session_state.username}** | MCKV Institute of Engineering")
    if col2.button("🚪 Logout"):
        st.session_state.logged_in = False
        st.session_state.token = None
        st.session_state.username = None
        st.rerun()

    st.markdown("---")
    st.sidebar.title("⚙️ Settings")
    st.sidebar.markdown(f"👤 **{st.session_state.username}**")
    st.sidebar.markdown("---")
    mode = st.sidebar.selectbox("Scan Mode", ["normal", "deep"],
        format_func=lambda x: "🔍 Normal Scan" if x == "normal" else "🔬 Deep Scan")

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
                        headers={"Authorization": f"Bearer {st.session_state.token}"},
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
                        headers={"Authorization": f"Bearer {st.session_state.token}"},
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

    st.markdown("---")
    if st.button("🏥 Check Backend Health"):
        try:
            res = requests.get(f"{BACKEND_URL}/health")
            data = res.json()
            if data["groq_api_key_loaded"]:
                st.success(f"✅ {data['message']}")
            else:
                st.error(f"❌ {data['message']}")
        except Exception:
            st.error("❌ Backend not reachable!")

if st.session_state.logged_in:
    page = st.sidebar.radio("📍 Navigate", ["🔍 Scanner", "👑 Admin"]) if st.session_state.get("is_admin") else "🔍 Scanner"
    if page == "👑 Admin":
        show_admin_dashboard()
    else:
        show_main_app()
else:
    show_auth_page()