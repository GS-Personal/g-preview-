import streamlit as st
import os
import base64
import json
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import uuid

st.set_page_config(page_title="G – Gmail Integration")

st.title("G – Your AI Assistant")
st.subheader("📧 Gmail Integration")

# Load credentials from secrets
client_id = st.secrets["client_id"]
client_secret = st.secrets["client_secret"]
redirect_uri = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"  # Replace with your deployed Streamlit URL

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Initialize oauth_state in session if not present
if "oauth_state" not in st.session_state:
    st.session_state.oauth_state = str(uuid.uuid4())

# Get current query parameters using the safer method
query_params = st.experimental_get_query_params()

# Check for returned OAuth code in query params
if "code" in query_params and "state" in query_params:
    # Verify state parameter to prevent CSRF attacks
    received_state = query_params.get("state", [""])[0]
    if received_state != st.session_state.oauth_state:
        st.error("⚠️ State verification failed. Please try connecting Gmail again.")
        # Clear the invalid query parameters
        st.experimental_set_query_params()
        st.rerun()
    
    try:
        auth_code = query_params.get("code", [""])[0]
        
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

        # Exchange the authorization code for credentials
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials

        # Save credentials to session
        st.session_state["credentials"] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }

        # Clear the query parameters to prevent reuse of the authorization code
        st.experimental_set_query_params()
        st.rerun()

    except Exception as e:
        st.error("⚠️ Login failed. The session may have expired or the code is invalid. Please try connecting Gmail again.")
        st.warning(f"🚨 Error during token fetch: {str(e)}")
        # Clear the invalid query parameters
        st.experimental_set_query_params()

# No credentials in session: show connect link
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
    # Include state parameter in authorization URL
    auth_url, _ = flow.authorization_url(
        prompt='consent',
        state=st.session_state.oauth_state,
        access_type='offline'  # Request a refresh token
    )
    st.markdown(f"🔗 [Click here to connect Gmail]({auth_url})")
    st.write("📌 Waiting for Gmail connection...")
else:
    # Show success state
    try:
        creds = Credentials.from_authorized_user_info(info=st.session_state["credentials"])
        
        # Check if token is expired and refresh if necessary
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Update the stored credentials
            st.session_state["credentials"] = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": creds.token_uri,
                "client_id": creds.client_id,
                "client_secret": creds.client_secret,
                "scopes": creds.scopes
            }
            
        st.success("✅ Gmail connected!")

        # Initialize Gmail API service
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
        st.error("Failed to fetch emails.")
        st.warning(f"🚨 Gmail API error: {str(e)}")
        # If token is invalid, clear credentials and prompt re-authentication
        if "invalid_grant" in str(e).lower() or "invalid_token" in str(e).lower():
            del st.session_state["credentials"]
            st.warning("Your Gmail session has expired. Please reconnect.")
            st.rerun()
