import streamlit as st
import os
import json
import uuid
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import openai

# Page configuration
st.set_page_config(page_title="G – Your AI Assistant", page_icon="🤖")

# App title and header
st.title("G – Your AI Assistant")

# Load credentials from secrets
CLIENT_ID = st.secrets["client_id"]
CLIENT_SECRET = st.secrets["client_secret"]
REDIRECT_URI = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
OPENAI_API_KEY = st.secrets["openai_api_key"]  # Add this to your Streamlit secrets

# Initialize OpenAI client
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# Debug information (collapsible)
with st.sidebar.expander("Debug Information", expanded=False):
    st.write("Session State Keys:", list(st.session_state.keys()))
    if "credentials" in st.session_state:
        st.write("Gmail Connected: Yes")
    else:
        st.write("Gmail Connected: No")
    st.write("Query Parameters:", dict(st.query_params))

# Function to get email data
def get_email_data():
    if "credentials" not in st.session_state:
        return None
    
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
        
        # Initialize Gmail API service
        service = build("gmail", "v1", credentials=credentials)
        
        # Fetch unread emails
        results = service.users().messages().list(userId="me", labelIds=["UNREAD"], maxResults=10).execute()
        messages = results.get("messages", [])
        
        email_data = []
        if messages:
            for msg in messages:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown Sender)")
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                snippet = msg_detail.get("snippet", "")
                
                email_data.append({
                    "subject": subject,
                    "sender": sender,
                    "date": date,
                    "snippet": snippet
                })
        
        return email_data
        
    except Exception as e:
        st.sidebar.error(f"Error fetching emails: {str(e)}")
        return None

# Function to generate AI response based on user input and email data
def generate_response(user_input, email_data):
    if not email_data:
        # If no email data is available
        system_message = """You are G, an AI assistant that helps with email-related queries. 
        Currently, you don't have access to any emails. You can only help with general questions."""
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_input}
        ]
    else:
        # Format email data for the AI
        email_context = "Here are your 10 most recent unread emails:\n\n"
        for i, email in enumerate(email_data, 1):
            email_context += f"Email {i}:\n"
            email_context += f"Subject: {email['subject']}\n"
            email_context += f"From: {email['sender']}\n"
            email_context += f"Date: {email['date']}\n"
            email_context += f"Preview: {email['snippet']}\n\n"
        
        system_message = """You are G, an AI assistant that helps with email-related queries.
        You have access to the user's recent unread emails and can provide insights or summaries based on them.
        Be helpful, concise, and respectful of privacy. When referring to emails, use specific details
        like subject lines or sender names to make it clear which email you're discussing."""
        
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"Here are my recent unread emails:\n\n{email_context}\n\nMy question is: {user_input}"}
        ]
    
    # Call OpenAI API
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=messages,
            temperature=0.7,
            max_tokens=500
        )
        return response.choices[0].message.content
    except Exception as e:
        st.sidebar.error(f"OpenAI API error: {str(e)}")
        return f"I'm sorry, I encountered an error while processing your request. Please try again later."

# Check for authorization code in query parameters (OAuth callback)
if "code" in st.query_params:
    try:
        auth_code = st.query_params["code"]
        
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
        st.query_params.clear()

# Main app interface
tabs = st.tabs(["Chat", "Emails", "Settings"])

with tabs[0]:  # Chat tab
    # Initialize chat history
    if "messages" not in st.session_state:
        st.session_state.messages = []

    # Display chat history
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("Talk to G..."):
        # Add user message to chat history
        st.session_state.messages.append({"role": "user", "content": prompt})
        
        # Display user message
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get email data (if available)
        email_data = get_email_data()
        
        # Display assistant response
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            
            # Generate AI response based on prompt and email data
            response = generate_response(prompt, email_data)
            
            # Display response
            message_placeholder.markdown(response)
        
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

with tabs[1]:  # Emails tab
    # Email section
    st.subheader("📧 Recent Unread Emails")
    
    # Check if gmail is connected
    if "credentials" not in st.session_state:
        # Gmail connection section
        st.info("Connect your Gmail account to access your emails")
        
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
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )
        
        # Display connect button
        st.markdown(f"🔗 [Connect Gmail]({auth_url})")
    else:
        # Display emails
        email_data = get_email_data()
        
        if not email_data:
            st.info("No unread emails found.")
        else:
            for i, email in enumerate(email_data, 1):
                with st.expander(f"📩 {email['subject']}"):
                    st.write(f"**From:** {email['sender']}")
                    st.write(f"**Date:** {email['date']}")
                    st.write("**Preview:**")
                    st.write(email['snippet'])

with tabs[2]:  # Settings tab
    st.subheader("⚙️ Settings")
    
    # Account connection status
    st.write("### Account Connections")
    
    if "credentials" in st.session_state:
        st.success("✅ Gmail connected!")
        if st.button("Disconnect Gmail"):
            del st.session_state["credentials"]
            st.rerun()
    else:
        st.warning("❌ Gmail not connected")
        
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
        
        # Generate authorization URL
        auth_url, _ = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent"
        )
        
        # Display connect button
        st.markdown(f"🔗 [Connect Gmail]({auth_url})")
    
    # Clear chat history option
    st.write("### Chat History")
    if st.button("Clear Chat History"):
        st.session_state.messages = []
        st.rerun()
