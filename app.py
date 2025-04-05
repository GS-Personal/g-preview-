import streamlit as st
import os
import uuid
import re
from datetime import datetime
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import openai
from collections import Counter

# Configuration and Setup
st.set_page_config(page_title="AI Communication Assistant", page_icon="🤖")

# Load credentials from secrets (ensure these are set in Streamlit secrets)
CLIENT_ID = st.secrets["client_id"]
CLIENT_SECRET = st.secrets["client_secret"]
REDIRECT_URI = "https://your-streamlit-app-url.streamlit.app"  # Replace with your actual URL
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
OPENAI_API_KEY = st.secrets["openai_api_key"]

# Initialize OpenAI client
openai_client = openai.OpenAI(api_key=OPENAI_API_KEY)

def get_top_contacts_from_gmail(service, max_emails=500, top_n=10):
    """
    Retrieve top contacts from Gmail based on email frequency.
    
    Args:
        service: Authenticated Gmail API service
        max_emails: Maximum number of emails to process
        top_n: Number of top contacts to return
    
    Returns:
        List of top contacts with their names and email addresses
    """
    try:
        # Fetch message IDs from inbox
        message_ids = []
        next_page_token = None

        while len(message_ids) < max_emails:
            results = service.users().messages().list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=min(100, max_emails - len(message_ids)),
                pageToken=next_page_token
            ).execute()

            message_ids.extend(results.get("messages", []))
            next_page_token = results.get("nextPageToken")
            
            if not next_page_token:
                break

        # Process senders from messages
        senders = []
        for msg in message_ids:
            try:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                sender_raw = next((h["value"] for h in headers if h["name"] == "From"), "")

                # Parse sender information
                match = re.match(r"(.*)<(.*)>", sender_raw)
                if match:
                    name = match.group(1).strip()
                    email = match.group(2).strip().lower()
                else:
                    name = sender_raw.strip()
                    email = sender_raw.strip().lower()

                # Filter out generic/automated senders
                if not re.search(r"(noreply|no-reply|mailer|notification|newsletter|receipt|support|do-not-reply)", email):
                    senders.append((name, email))
            except Exception as msg_error:
                st.sidebar.warning(f"Error processing message: {msg_error}")

        # Count and return top contacts
        counter = Counter(senders)
        return counter.most_common(top_n)

    except Exception as e:
        st.error(f"Error fetching top contacts: {e}")
        return []

def get_email_data(service):
    """
    Retrieve recent unread emails from Gmail.
    
    Args:
        service: Authenticated Gmail API service
    
    Returns:
        List of email dictionaries with basic information
    """
    try:
        # Fetch unread emails
        results = service.users().messages().list(userId="me", labelIds=["UNREAD"], maxResults=10).execute()
        messages = results.get("messages", [])
        
        email_data = []
        for msg in messages:
            try:
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                # Extract email details
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
            except Exception as msg_error:
                st.sidebar.warning(f"Error processing email: {msg_error}")
        
        return email_data
        
    except Exception as e:
        st.error(f"Error fetching emails: {e}")
        return []

def generate_ai_response(user_input, email_data=None):
    """
    Generate AI response based on user input and email context.
    
    Args:
        user_input: User's message
        email_data: Optional list of recent emails
    
    Returns:
        AI-generated response string
    """
    # Prepare context
    context_parts = []
    
    if email_data:
        email_context = "Recent unread emails:\n\n"
        for i, email in enumerate(email_data, 1):
            email_context += (
                f"Email {i}:\n"
                f"Subject: {email['subject']}\n"
                f"From: {email['sender']}\n"
                f"Date: {email['date']}\n"
                f"Preview: {email['snippet']}\n\n"
            )
        context_parts.append(email_context)
    
    # Determine system prompt
    system_message = (
        "You are an AI assistant that helps analyze and provide insights about communications. "
        "You can reference recent emails if they are available. Be helpful, concise, and respectful."
    )
    
    user_message = (
        context_parts[0] if context_parts 
        else "No recent email context available. " + user_input
    )
    
    # Combine context if exists
    full_user_message = (
        f"{user_message}\n\nMy specific question is: {user_input}"
        if context_parts 
        else user_input
    )
    
    try:
        # Generate AI response
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": full_user_message}
            ],
            temperature=0.7,
            max_tokens=500
        )
        return response.choices[0].message.content
    
    except Exception as e:
        st.error(f"Error generating AI response: {e}")
        return "I'm sorry, I encountered an error while processing your request."

def main():
    """
    Main Streamlit application
    """
    st.title("AI Communication Assistant 🤖")
    
    # Check for OAuth callback
    if "code" in st.query_params:
        try:
            # Create OAuth flow
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
            flow.fetch_token(code=st.query_params["code"])
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
            st.error(f"Gmail authentication error: {e}")
            st.warning("Please try connecting Gmail again.")
            st.query_params.clear()
    
    # Main application tabs
    tabs = st.tabs(["Chat", "Emails", "Settings"])
    
    with tabs[0]:  # Chat Tab
        # Initialize chat history
        if "messages" not in st.session_state:
            st.session_state.messages = []
        
        # Display chat history
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])
        
        # Chat input
        if prompt := st.chat_input("Talk to your AI assistant..."):
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Prepare email context if Gmail is connected
            email_data = None
            if "gmail_credentials" in st.session_state:
                try:
                    # Recreate credentials
                    creds_dict = st.session_state["gmail_credentials"]
                    credentials = Credentials(
                        token=creds_dict["token"],
                        refresh_token=creds_dict.get("refresh_token"),
                        token_uri=creds_dict["token_uri"],
                        client_id=creds_dict["client_id"],
                        client_secret=creds_dict["client_secret"],
                        scopes=creds_dict["scopes"]
                    )
                    
                    # Refresh token if expired
                    if credentials.expired and credentials.refresh_token:
                        credentials.refresh(Request())
                        # Update stored credentials
                        st.session_state["gmail_credentials"]["token"] = credentials.token
                    
                    # Build Gmail service
                    service = build("gmail", "v1", credentials=credentials)
                    
                    # Get email data
                    email_data = get_email_data(service)
                    
                except Exception as e:
                    st.error(f"Error accessing Gmail: {e}")
            
            # Generate AI response
            with st.chat_message("assistant"):
                response = generate_ai_response(prompt, email_data)
                st.markdown(response)
            
            # Add assistant response to chat history
            st.session_state.messages.append({"role": "assistant", "content": response})
    
    with tabs[1]:  # Emails Tab
        st.subheader("📧 Email Management")
        
        # Check Gmail connection
        if "gmail_credentials" not in st.session_state:
            st.info("Connect your Gmail account to access emails")
            
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
            # Recreate credentials
            try:
                creds_dict = st.session_state["gmail_credentials"]
                credentials = Credentials(
                    token=creds_dict["token"],
                    refresh_token=creds_dict.get("refresh_token"),
                    token_uri=creds_dict["token_uri"],
                    client_id=creds_dict["client_id"],
                    client_secret=creds_dict["client_secret"],
                    scopes=creds_dict["scopes"]
                )
                
                # Refresh token if expired
                if credentials.expired and credentials.refresh_token:
                    credentials.refresh(Request())
                
                # Build Gmail service
                service = build("gmail", "v1", credentials=credentials)
                
                # Section: Top Contacts
                st.subheader("📇 Top Contacts")
                top_contacts = get_top_contacts_from_gmail(service)
                if top_contacts:
                    for name, email in top_contacts:
                        st.markdown(f"**{name}**\n{email}")
                else:
                    st.info("No top contacts found.")
                
                # Section: Recent Emails
                st.subheader("📬 Recent Unread Emails")
                email_data = get_email_data(service)
                
                if not email_data:
                    st.info("No unread emails found.")
                else:
                    for email in email_data:
                        with st.expander(f"📧 {email['subject']}"):
                            st.write(f"**From:** {email['sender']}")
                            st.write(f"**Date:** {email['date']}")
                            st.write("**Preview:**")
                            st.write(email['snippet'])
            
            except Exception as e:
                st.error(f"Error accessing Gmail: {e}")
                # Option to reconnect
                if st.button("Reconnect Gmail"):
                    del st.session_state["gmail_credentials"]
                    st.rerun()
    
    with tabs[2]:  # Settings Tab
        st.subheader("⚙️ Settings")
        
        # Gmail Connection Status
        st.write("### Account Connection")
        if "gmail_credentials" in st.session_state:
            st.success("✅ Gmail Connected")
            if st.button("Disconnect Gmail"):
                del st.session_state["gmail_credentials"]
                st.rerun()
        else:
            st.warning("❌ Gmail Not Connected")
        
        # Chat History Management
        st.write("### Chat History")
        if st.button("Clear Chat History"):
            st.session_state.messages = []
            st.rerun()
        
        # App Information
        st.write("### About")
        st.write("""
        **AI Communication Assistant** helps you analyze and manage your emails.
        
        Features:
        - Chat with AI about your emails
        - View recent communications
        - Get insights from your inbox
        
        Version: 1.1
        """)

if __name__ == "__main__":
    main()
