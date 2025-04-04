
import streamlit as st
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import os
import json

st.set_page_config(page_title="G – Gmail Integration")

st.title("G – Your AI Assistant")
st.subheader("🔐 Connect your Gmail account")

# Path to store token.json temporarily
TOKEN_FILE = "token.json"

client_id = st.secrets["client_id"]
client_secret = st.secrets["client_secret"]

flow = Flow.from_client_config(
    {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": ["https://i4gbxwyduex7sferh9ktbc.streamlit.app"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    },
    scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    redirect_uri="https://i4gbxwyduex7sferh9ktbc.streamlit.app"
)

if "credentials" not in st.session_state:
    auth_url, _ = flow.authorization_url(prompt='consent')
    st.markdown(f"[Click here to connect Gmail]({auth_url})")
else:
    creds = Credentials.from_authorized_user_info(info=st.session_state["credentials"])
    st.success("✅ Gmail connected!")

# Placeholder for where we'll fetch + display emails
st.markdown("---")
st.write("📥 Once connected, G will fetch your latest unread emails and summarize them here.")
