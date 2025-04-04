
import streamlit as st
import os
import base64
import json
import requests
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

st.set_page_config(page_title="G – Gmail Fetch")

st.title("G – Your AI Assistant")
st.subheader("📧 Gmail Integration")

# Setup
client_id = st.secrets["client_id"]
client_secret = st.secrets["client_secret"]
redirect_uri = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

if "credentials" not in st.session_state:
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uris": [redirect_uri],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    auth_url, _ = flow.authorization_url(prompt='consent')
    st.markdown(f"[Click here to connect Gmail]({auth_url})")
else:
    creds = Credentials.from_authorized_user_info(info=st.session_state["credentials"])
    st.success("✅ Gmail connected!")

    # Call Gmail API to get last 10 unread emails
    try:
        service = build("gmail", "v1", credentials=creds)
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
                st.write(f"- {subject}")
    except Exception as e:
        st.error(f"Failed to fetch emails: {e}")
