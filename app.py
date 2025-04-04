import streamlit as st
import os
import json
import uuid
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

st.set_page_config(page_title="G – Gmail Integration")

st.title("G – Your AI Assistant")
st.subheader("📧 Gmail Integration")

# Load credentials from secrets
CLIENT_ID = st.secrets["client_id"]
CLIENT_SECRET = st.secrets["client_secret"]
REDIRECT_URI = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Debug information
with st.sidebar.expander("Debug Information", expanded=True):
    st.write("Session State Keys:", list(st.session_state.keys()))
    if "credentials" in st.session_state:
        st.write("Has Credentials: Yes")
    st.write("Query Parameters:", dict(st.query_params))

# Check for authorization code in query parameters
if "code" in st.query_params and "state" in st.query_params:
    try:
        auth_code = st.query_params["code"]
        
        # Debug
        with st.sidebar:
            st.write("Auth code received:", auth_code[:10] + "...")
            
        # Create flow instance
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "redirect_uris": [REDIRECT_URI],
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token"
                }
            },
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        
        # Exchange authorization code for credentials
        flow.fetch_token(code=auth_code)
        credentials = flow.credentials
        
        # Debug
        with st.sidebar:
            st.write("Token fetch successful")
            if credentials.token:
                st.write("Access token received:", credentials.token[:10] + "...")
            if credentials.refresh_token:
                st.write("Refresh token received:", credentials.refresh_token[:10] + "...")
        
        # Store credentials in session state
        st.session_state["credentials"] = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes
        }
        
        # Clear query parameters
        st.query_params.clear()
        st.rerun()
            
    except Exception as e:
        st.error(f"⚠️ Authentication error: {str(e)}")
        st.warning("Please try connecting Gmail again.")
        
        # Debug
        with st.sidebar:
            st.write("Auth error:", str(e))
            import traceback
            st.text(traceback.format_exc())
            
        # Clear query parameters
        st.query_params.clear()

# Display appropriate UI based on authentication status
if "credentials" not in st.session_state:
    # Not authenticated yet - show connect button
    st.write("Connect your Gmail account to access your emails.")
    
    # Create flow instance for authorization URL
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uris": [REDIRECT_URI],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token"
            }
        },
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    
    # Generate authorization URL without state parameter
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent"
    )
    
    # Display direct link
    st.markdown(f"🔗 [Click here to connect Gmail]({auth_url})")
    st.write("📌 Waiting for Gmail connection...")
    
    # Alternative button
    if st.button("Connect Gmail (Alternative)"):
        st.info(f"Redirecting to Google authentication...")
        st.markdown(f"<meta http-equiv='refresh' content='0;URL={auth_url}'>", unsafe_allow_html=True)
    
else:
    # Already authenticated - display emails
    try:
        # Recreate credentials object
        creds_dict = st.session_state["credentials"]
        credentials = Credentials(
            token=creds_dict["token"],
            refresh_token=creds_dict.get("refresh_token"),
            token_uri=creds_dict["token_uri"],
            client_id=creds_dict["client_id"],
            client_secret=creds_dict["client_secret"],
            scopes=creds_dict["scopes"]
        )
        
        # Check if token is expired and refresh if needed
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            # Update stored credentials
            st.session_state["credentials"] = {
                "token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "token_uri": credentials.token_uri,
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
                "scopes": credentials.scopes
            }
        
        st.success("✅ Gmail connected!")
        
        # Initialize Gmail API service
        service = build("gmail", "v1", credentials=credentials)
        
        # Fetch unread emails
        results = service.users().messages().list(userId="me", labelIds=["UNREAD"], maxResults=10).execute()
        messages = results.get("messages", [])
        
        if not messages:
            st.info("No unread emails found.")
        else:
            st.subheader("🔟 Last 10 Unread Emails")
            
            for msg in messages:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown Sender)")
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                
                with st.expander(f"📩 {subject}"):
                    st.write(f"**From:** {sender}")
                    st.write(f"**Date:** {date}")
                    
                    # Try to get snippet or body
                    if "snippet" in msg_detail:
                        st.write("**Preview:**")
                        st.write(msg_detail["snippet"])
        
        # Add disconnect button
        if st.button("Disconnect Gmail"):
            del st.session_state["credentials"]
            st.rerun()
            
    except Exception as e:
        st.error(f"Failed to fetch emails: {str(e)}")
        
        # Debug
        with st.sidebar:
            st.write("Gmail API error:", str(e))
            
        # Handle invalid credentials
        if "invalid_grant" in str(e).lower() or "invalid_token" in str(e).lower():
            st.warning("Your Gmail session has expired. Please reconnect.")
            if "credentials" in st.session_state:
                del st.session_state["credentials"]
            st.rerun()
