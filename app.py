import streamlit as st
import os
import json
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
import streamlit_oauth as oauth

st.set_page_config(page_title="G – Gmail Integration")

st.title("G – Your AI Assistant")
st.subheader("📧 Gmail Integration")

# Configuration
CLIENT_ID = st.secrets["client_id"]
CLIENT_SECRET = st.secrets["client_secret"]
REDIRECT_URI = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
AUTH_URL = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"

# Initialize the OAuth handler
oauth_handler = oauth.OAuth2(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    authorize_endpoint=AUTH_URL,
    token_endpoint=TOKEN_URL,
    refresh_endpoint=TOKEN_URL,
    revoke_endpoint="https://oauth2.googleapis.com/revoke",
    redirect_uri=REDIRECT_URI,
    scope=SCOPES,
)

# For debugging
debug_expander = st.sidebar.expander("Debug Information", expanded=True)
with debug_expander:
    st.write("Session State Keys:", list(st.session_state.keys()))
    st.write("Is Authenticated:", oauth_handler.is_authenticated())
    if "token_info" in st.session_state:
        st.write("Has Token Info: Yes")

# Create "Login with Google" button
if not oauth_handler.is_authenticated():
    # Not authenticated yet, show the login button
    if st.button("🔗 Connect Gmail"):
        # Redirect to Google's authorization page
        authorization_url = oauth_handler.get_authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true"
        )
        st.markdown(f"Redirecting to Google... [Click here if not redirected]({authorization_url})")
        # Use JavaScript to redirect
        st.components.v1.html(
            f"""
            <script>
            window.top.location.href = "{authorization_url}";
            </script>
            """,
            height=0,
        )
    st.write("📌 Waiting for Gmail connection...")
else:
    # Already authenticated
    st.success("✅ Gmail connected!")
    
    # Get a fresh token if needed
    token_info = oauth_handler.get_token()
    
    # Create credentials object from token info
    creds = Credentials(
        token=token_info["access_token"],
        refresh_token=token_info.get("refresh_token"),
        token_uri=TOKEN_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        scopes=SCOPES
    )
    
    try:
        # Initialize Gmail API
        service = build("gmail", "v1", credentials=creds)
        
        # Fetch unread emails
        results = service.users().messages().list(userId="me", labelIds=["UNREAD"], maxResults=10).execute()
        messages = results.get("messages", [])
        
        if not messages:
            st.info("No unread emails found.")
        else:
            st.markdown("### 🔟 Last 10 Unread Email Subjects:")
            for msg in messages:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown Sender)")
                st.write(f"- **{subject}** from {sender}")
        
        # Add logout button
        if st.button("Disconnect Gmail"):
            oauth_handler.logout()
            st.rerun()
            
    except Exception as e:
        st.error("Failed to fetch emails.")
        st.warning(f"🚨 Gmail API error: {str(e)}")
        
        # Check if token expired or invalid
        if "invalid_grant" in str(e).lower() or "invalid_token" in str(e).lower():
            st.warning("Your Gmail session has expired. Please reconnect.")
            oauth_handler.logout()
            st.rerun()
