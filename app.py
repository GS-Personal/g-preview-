import streamlit as st
import os
import json
import uuid
import time
from datetime import datetime
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import openai
import requests

# Page configuration
st.set_page_config(page_title="G – Your AI Assistant", page_icon="🤖")

# App title and header
st.title("G – Your AI Assistant")

# Load credentials from secrets
CLIENT_ID = st.secrets["client_id"]
CLIENT_SECRET = st.secrets["client_secret"]
REDIRECT_URI = "https://i4gbxwyduex7sferh9ktbc.streamlit.app"
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
OPENAI_API_KEY = st.secrets["openai_api_key"]

# Slack credentials - add these to your Streamlit secrets
SLACK_CLIENT_ID = st.secrets.get("slack_client_id", "")
SLACK_CLIENT_SECRET = st.secrets.get("slack_client_secret", "")
SLACK_REDIRECT_URI = REDIRECT_URI  # Using the same redirect URI

# Initialize OpenAI client
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# Debug information (collapsible)
with st.sidebar.expander("Debug Information", expanded=False):
    st.write("Session State Keys:", list(st.session_state.keys()))
    if "gmail_credentials" in st.session_state:
        st.write("Gmail Connected: Yes")
    else:
        st.write("Gmail Connected: No")
    if "slack_credentials" in st.session_state:
        st.write("Slack Connected: Yes")
    else:
        st.write("Slack Connected: No")
    st.write("Query Parameters:", dict(st.query_params))

# Function to get email data
def get_email_data():
    if "gmail_credentials" not in st.session_state:
        return None
    
    try:
        # Recreate credentials object
        creds_dict = st.session_state["gmail_credentials"]
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
            st.session_state["gmail_credentials"] = {
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

# Function to get Slack messages
def get_slack_messages():
    if "slack_credentials" not in st.session_state:
        return None
    
    try:
        # Validate credentials structure with debugging
        if not isinstance(st.session_state["slack_credentials"], dict):
            st.sidebar.error(f"slack_credentials is not a dictionary: {type(st.session_state['slack_credentials'])}")
            return None
        
        # Check if access_token exists
        if "access_token" not in st.session_state["slack_credentials"]:
            st.sidebar.error("No access_token found in slack_credentials")
            return None
        
        # Get access token with safe checking
        access_token = st.session_state["slack_credentials"].get("access_token")
        
        if not access_token:
            st.sidebar.error("Access token is empty")
            return None
            
        # Debug token info
        token_preview = access_token[:5] + "..." + access_token[-5:] if len(access_token) > 10 else "too short"
        st.sidebar.write(f"Token preview: {token_preview}")
        
        # Get list of channels
        headers = {
            "Authorization": f"Bearer {access_token}"
        }
        
        # Get conversations (channels) list
        channels_response = requests.get("https://slack.com/api/conversations.list", headers=headers)
        channels_data = channels_response.json()
        
        # Debug the response
        st.sidebar.write("API Response status:", channels_response.status_code)
        if "error" in channels_data:
            st.sidebar.error(f"Slack API error: {channels_data.get('error')}")
        
        if not channels_data.get("ok", False):
            error_msg = channels_data.get("error", "Unknown error")
            st.sidebar.error(f"Error fetching Slack channels: {error_msg}")
            
            # If token is invalid, clear credentials
            if error_msg == "invalid_auth" or error_msg == "not_authed":
                st.sidebar.warning("Invalid Slack token. Please reconnect.")
                if "slack_credentials" in st.session_state:
                    del st.session_state["slack_credentials"]
                return None
                
        channels = channels_data.get("channels", [])
        
        # Get messages from each channel
        all_messages = []
        
        # Limit to 5 channels for performance
        for channel in channels[:5]:
            channel_id = channel["id"]
            channel_name = channel["name"]
            
            # Get messages from this channel
            messages_response = requests.get(
                "https://slack.com/api/conversations.history",
                headers=headers,
                params={"channel": channel_id, "limit": 5}  # Limit to 5 messages per channel
            )
            
            messages_data = messages_response.json()
            
            if not messages_data.get("ok", False):
                st.sidebar.warning(f"Could not fetch messages for channel {channel_name}: {messages_data.get('error', 'Unknown error')}")
                continue
                
            messages = messages_data.get("messages", [])
            
            for msg in messages:
                # Format timestamp
                ts = float(msg.get("ts", 0))
                date_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                
                # Get user info - with safer handling
                user_id = msg.get("user", "Unknown")
                user_info = "Unknown User"
                
                if user_id != "Unknown":
                    try:
                        user_response = requests.get(
                            "https://slack.com/api/users.info",
                            headers=headers,
                            params={"user": user_id}
                        )
                        user_data = user_response.json()
                        
                        if user_data.get("ok", False):
                            # Safely navigate nested dictionary
                            user_obj = user_data.get("user", {})
                            user_info = user_obj.get("real_name", "Unknown User")
                    except Exception as user_error:
                        st.sidebar.warning(f"Error fetching user info: {str(user_error)}")
                
                all_messages.append({
                    "channel": channel_name,
                    "user": user_info,
                    "text": msg.get("text", ""),
                    "date": date_str
                })
                
                # Respect rate limits
                time.sleep(0.5)
        
        return all_messages
        
    except Exception as e:
        st.sidebar.error(f"Error fetching Slack messages: {str(e)}")
        # Print more detailed error information
        import traceback
        st.sidebar.text(traceback.format_exc())
        return None

# Function to generate AI response based on user input and data
def generate_response(user_input, email_data=None, slack_data=None):
    # Initialize context parts
    context_parts = []
    
    # Add email context if available
    if email_data:
        email_context = "Recent unread emails:\n\n"
        for i, email in enumerate(email_data, 1):
            email_context += f"Email {i}:\n"
            email_context += f"Subject: {email['subject']}\n"
            email_context += f"From: {email['sender']}\n"
            email_context += f"Date: {email['date']}\n"
            email_context += f"Preview: {email['snippet']}\n\n"
        context_parts.append(email_context)
    
    # Add slack context if available
    if slack_data:
        slack_context = "Recent Slack messages:\n\n"
        for i, msg in enumerate(slack_data, 1):
            slack_context += f"Message {i}:\n"
            slack_context += f"Channel: #{msg['channel']}\n"
            slack_context += f"From: {msg['user']}\n"
            slack_context += f"Date: {msg['date']}\n"
            slack_context += f"Content: {msg['text']}\n\n"
        context_parts.append(slack_context)
    
    # Determine system prompt based on available data
    if not context_parts:
        system_message = """You are G, an AI assistant that helps with general questions. 
        Currently, you don't have access to any emails or Slack messages. You can only help with general questions."""
        user_message = user_input
    else:
        system_message = """You are G, an AI assistant that helps with communication-related queries.
        You have access to the user's recent messages and can provide insights or summaries based on them.
        Be helpful, concise, and respectful of privacy. When referring to messages, use specific details
        like email subjects, sender names, or Slack channels to make it clear which message you're discussing."""
        
        context_text = "\n".join(context_parts)
        user_message = f"Here is my recent communication data:\n\n{context_text}\n\nMy question is: {user_input}"
    
    # Call OpenAI API
    try:
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message}
        ]
        
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
    # Determine which service this is for based on state parameter
    if "state" in st.query_params and st.query_params["state"].startswith("slack_"):
        # This is Slack OAuth callback
        try:
            auth_code = st.query_params["code"]
            
            # Debug info
            st.sidebar.write("Processing Slack OAuth callback")
            
            # Exchange code for token
            response = requests.post(
                "https://slack.com/api/oauth.v2.access",
                data={
                    "client_id": SLACK_CLIENT_ID,
                    "client_secret": SLACK_CLIENT_SECRET,
                    "code": auth_code,
                    "redirect_uri": SLACK_REDIRECT_URI
                }
            )
            
            # Debug response
            st.sidebar.write("Slack API response status:", response.status_code)
            
            token_data = response.json()
            
            # Debug token data (safely without exposing sensitive info)
            st.sidebar.write("Response contains 'ok':", "ok" in token_data)
            st.sidebar.write("Response has access_token:", "access_token" in token_data)
            
            if not token_data.get("ok", False):
                st.error(f"⚠️ Slack authentication error: {token_data.get('error', 'Unknown error')}")
            else:
                # Extract values with safe defaults
                access_token = token_data.get("access_token")
                team_info = token_data.get("team", {})
                user_info = token_data.get("authed_user", {})
                
                if not access_token:
                    st.error("No access token received from Slack")
                else:
                    # Store token info
                    st.session_state["slack_credentials"] = {
                        "access_token": access_token,
                        "team_name": team_info.get("name", "Unknown Workspace") if team_info else "Unknown Workspace",
                        "user_id": user_info.get("id") if user_info else None
                    }
                    st.success("✅ Slack connected successfully!")
            
            # Clear query parameters
            st.query_params.clear()
            st.rerun()
            
        except Exception as e:
            st.error(f"⚠️ Slack authentication error: {str(e)}")
            import traceback
            st.sidebar.text(traceback.format_exc())
            st.query_params.clear()
    else:
        # This is Gmail OAuth callback
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
                scopes=GMAIL_SCOPES,
                redirect_uri=REDIRECT_URI
            )
            
            # Exchange authorization code for credentials
            flow.fetch_token(code=auth_code)
            credentials = flow.credentials
            
            # Store credentials in session state
            st.session_state["gmail_credentials"] = {
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
            st.error(f"⚠️ Gmail authentication error: {str(e)}")
            st.warning("Please try connecting Gmail again.")
            st.query_params.clear()

# Main app interface
tabs = st.tabs(["Chat", "Communications", "Settings"])

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
        
        # Get email and slack data (if available)
        email_data = get_email_data() if "gmail_credentials" in st.session_state else None
        slack_data = get_slack_messages() if "slack_credentials" in st.session_state else None
        
        # Display assistant response
        with st.chat_message("assistant"):
            message_placeholder = st.empty()
            
            # Generate AI response based on prompt and available data
            response = generate_response(prompt, email_data, slack_data)
            
            # Display response
            message_placeholder.markdown(response)
        
        # Add assistant response to chat history
        st.session_state.messages.append({"role": "assistant", "content": response})

with tabs[1]:  # Communications tab
    # Create tabs for different communication sources
    comm_tabs = st.tabs(["Emails", "Slack"])
    
    with comm_tabs[0]:  # Emails tab
        st.subheader("📧 Recent Unread Emails")
        
        # Check if gmail is connected
        if "gmail_credentials" not in st.session_state:
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
                scopes=GMAIL_SCOPES,
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
    
    with comm_tabs[1]:  # Slack tab
        st.subheader("💬 Recent Slack Messages")
        
        # Check if slack is connected
        if "slack_credentials" not in st.session_state:
            # Slack connection section
            st.info("Connect your Slack account to access your messages")
            
            # Generate Slack authorization URL with a state parameter to identify it's for Slack
            state_param = f"slack_{str(uuid.uuid4())}"
            auth_url = (
                f"https://slack.com/oauth/v2/authorize"
                f"?client_id={SLACK_CLIENT_ID}"
                f"&user_scope=channels:history,channels:read,groups:history,groups:read,users:read"
                f"&redirect_uri={SLACK_REDIRECT_URI}"
                f"&state={state_param}"
            )
            
            # Display connect button
            st.markdown(
            f"""
            <a href="{auth_url}" target="_self">🔗 Connect Slack</a>
            """, 
            unsafe_allow_html=True
            )
        else:
            # Display team name
            team_name = st.session_state["slack_credentials"].get("team_name", "Your Workspace")
            st.write(f"Connected to: **{team_name}**")
            
            # Display messages
            slack_data = get_slack_messages()
            
            if not slack_data:
                st.info("No recent Slack messages found.")
            else:
                # Group messages by channel
                channels = {}
                for msg in slack_data:
                    channel = msg["channel"]
                    if channel not in channels:
                        channels[channel] = []
                    channels[channel].append(msg)
                
                # Display messages by channel
                for channel, messages in channels.items():
                    st.write(f"### #{channel}")
                    for msg in messages:
                        with st.expander(f"{msg['user']} - {msg['date']}"):
                            st.write(msg["text"])
                    st.write("---")

with tabs[2]:  # Settings tab
    st.subheader("⚙️ Settings")
    
    # Account connection status
    st.write("### Account Connections")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Gmail Status:**")
        if "gmail_credentials" in st.session_state:
            st.success("✅ Connected")
            if st.button("Disconnect Gmail"):
                del st.session_state["gmail_credentials"]
                st.rerun()
        else:
            st.warning("❌ Not connected")
            
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
                scopes=GMAIL_SCOPES,
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
    
    with col2:
        st.write("**Slack Status:**")
        if "slack_credentials" in st.session_state:
            st.success(f"✅ Connected to {st.session_state['slack_credentials'].get('team_name', 'Slack')}")
            if st.button("Disconnect Slack"):
                del st.session_state["slack_credentials"]
                st.rerun()
        else:
            st.warning("❌ Not connected")
            
            # Generate Slack authorization URL
            state_param = f"slack_{str(uuid.uuid4())}"
            auth_url = (
                f"https://slack.com/oauth/v2/authorize"
                f"?client_id={SLACK_CLIENT_ID}"
                f"&user_scope=channels:history,channels:read,groups:history,groups:read,users:read"
                f"&redirect_uri={SLACK_REDIRECT_URI}"
                f"&state={state_param}"
            )
            
           # Display connect button
            st.markdown(
             f"""
            <a href="{auth_url}" target="_self">🔗 Connect Slack</a>
            """, 
            unsafe_allow_html=True
            )

            st.write("---")  # Fix: This line needs to be at the same indentation level as the lines above

            # Clear chat history option
            st.write("### Chat History")
            if st.button("Clear Chat History"):
            st.session_state.messages = []
            st.rerun()

            st.write("---")
    
    # App information
    st.write("### About")
    st.write("""
    **G – Your AI Assistant** helps you analyze and manage your communications.
    
    Features:
    - Chat with AI about your emails and Slack messages
    - View recent communications in one place
    - Get insights and summaries of your messages
    
    Version: 1.0
    """)
