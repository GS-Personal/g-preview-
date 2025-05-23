import streamlit as st
import os
import json
import uuid
import time
import base64
from datetime import datetime
from dateutil import parser as date_parser
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import openai
import requests
import re
from collections import Counter

# Page configuration
st.set_page_config(page_title="G – Your AI Assistant", page_icon="🤖")

# App title and header
st.title("G – Your AI Assistant")

# Use a more persistent state parameter
if "persistent_slack_state" not in st.session_state:
    st.session_state.persistent_slack_state = str(uuid.uuid4())

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

# Manual OAuth code input
if "manual_slack_code" not in st.session_state:
    st.session_state.manual_slack_code = ""

# Enhanced Debug section
with st.sidebar.expander("Debug Information", expanded=False):
    st.write("Session State Keys:", list(st.session_state.keys()))
    if "gmail_credentials" in st.session_state:
        st.write("Gmail Connected: Yes")
    else:
        st.write("Gmail Connected: No")
    if "slack_credentials" in st.session_state:
        st.write("Slack Connected: Yes")
        st.write("Slack Team:", st.session_state["slack_credentials"].get("team_name", "Unknown"))
    else:
        st.write("Slack Connected: No")
    st.write("Query Parameters:", dict(st.query_params))
    
    # Add persistent state debugging
    st.write("Persistent Slack State:", st.session_state.get("persistent_slack_state", "Not set"))
    
    # Add OAuth debug information
    st.write("### OAuth Debug")
    if "code" in st.query_params:
        st.write("Authorization Code Present: YES")
        st.write("Code First 10 chars:", st.query_params["code"][:10] + "...")
    else:
        st.write("Authorization Code Present: NO")
    
    if "state" in st.query_params:
        st.write("State Parameter Present: YES")
        st.write("State Value:", st.query_params["state"])
        if st.query_params["state"].startswith("slack_"):
            st.write("Is Slack State: YES")
        else:
            st.write("Is Slack State: NO")
    else:
        st.write("State Parameter Present: NO")

# Function to get the authenticated user's email address
def get_user_email_address(service):
    """Get the email address of the authenticated user"""
    try:
        profile = service.users().getProfile(userId='me').execute()
        return profile.get('emailAddress')
    except Exception as e:
        st.sidebar.error(f"Error fetching user profile: {str(e)}")
        return None

# Function to parse date strings
def parse_date(date_string):
    try:
        return date_parser.parse(date_string)
    except Exception:
        return datetime.min  # Default to minimum date if parsing fails

# Modified email fetching function to get both incoming and outgoing emails
def get_email_data(max_emails=10, analyze_contacts=False):
    if "gmail_credentials" not in st.session_state:
        return None, None
    
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
        
        # Get user's own email address
        user_email = get_user_email_address(service)
        
        # Fetch emails - use a larger number if analyzing contacts
        fetch_count = 500 if analyze_contacts else max_emails
        
        # Get both received and sent emails
        received_results = service.users().messages().list(
            userId="me", 
            maxResults=fetch_count // 2,
            q="in:inbox"
        ).execute()
        
        sent_results = service.users().messages().list(
            userId="me", 
            maxResults=fetch_count // 2,
            q="in:sent"
        ).execute()
        
        received_messages = received_results.get("messages", [])
        sent_messages = sent_results.get("messages", [])
        
        # Combine and process messages
        all_messages = []
        if received_messages:
            all_messages.extend([(msg, "incoming") for msg in received_messages])
        if sent_messages:
            all_messages.extend([(msg, "outgoing") for msg in sent_messages])
            
        # If we need to limit total count
        all_messages = all_messages[:fetch_count]
        
        email_data = []
        contact_counter = Counter()
        contact_emails = {}  # Store email addresses with contact names
        system_domains = ["noreply", "no-reply", "donotreply", "automated", "notification", "alert", "updates", 
                         "newsletter", "info@", "support@", "help@", "service@", "billing@", "account@"]
        
        if all_messages:
            for msg_tuple in all_messages:
                msg, direction = msg_tuple
                
                # Display a progress bar if analyzing many emails
                if analyze_contacts and len(all_messages) > 20:
                    progress_text = f"Analyzing emails... ({len(email_data)+1}/{len(all_messages)})"
                    if 'progress_bar' not in st.session_state:
                        st.session_state.progress_bar = st.progress(0.0, text=progress_text)
                    else:
                        st.session_state.progress_bar.progress((len(email_data)+1)/len(all_messages), text=progress_text)
                
                # Get message details
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                
                # Get sender and recipient according to direction
                sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown Sender)")
                recipient = next((h["value"] for h in headers if h["name"] == "To"), "(Unknown Recipient)")
                
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                snippet = msg_detail.get("snippet", "")
                
                # Add to email data
                email_data.append({
                    "subject": subject,
                    "sender": sender,
                    "recipient": recipient,
                    "date": date,
                    "snippet": snippet,
                    "direction": direction
                })
                
                # For contact analysis, count the other party, not the user
                if analyze_contacts:
                    if direction == "incoming":
                        # Count sender (but not if it's a system email)
                        email_pattern = r'[\w\.-]+@[\w\.-]+'
                        email_match = re.search(email_pattern, sender)
                        email_address = email_match.group(0) if email_match else ""
                        
                        # Skip if this is the user's email or a system email
                        is_system_email = any(domain in email_address.lower() for domain in system_domains)
                        if email_address and email_address != user_email and not is_system_email:
                            name_pattern = r'^([^<]+)'
                            name_match = re.search(name_pattern, sender)
                            display_name = name_match.group(1).strip() if name_match else email_address
                            contact_counter[display_name] += 1
                            # Store the email address with the contact name
                            contact_emails[display_name] = email_address
                    else:
                        # For outgoing emails, count recipients
                        email_pattern = r'[\w\.-]+@[\w\.-]+'
                        email_matches = re.findall(email_pattern, recipient)
                        
                        for email_address in email_matches:
                            # Skip if this is the user's email or a system email
                            is_system_email = any(domain in email_address.lower() for domain in system_domains)
                            if email_address and email_address != user_email and not is_system_email:
                                # Try to find a name in the recipient string
                                recipient_parts = recipient.split(",")
                                for part in recipient_parts:
                                    if email_address in part:
                                        name_pattern = r'^([^<]+)'
                                        name_match = re.search(name_pattern, part)
                                        display_name = name_match.group(1).strip() if name_match else email_address
                                        contact_counter[display_name] += 1
                                        # Store the email address with the contact name
                                        contact_emails[display_name] = email_address
                                        break
        
        # If we were using a progress bar, complete it and clear
        if analyze_contacts and 'progress_bar' in st.session_state:
            st.session_state.progress_bar.progress(1.0, text="Analysis complete!")
            del st.session_state.progress_bar
        
        # Store contact emails in session state
        if analyze_contacts and contact_emails:
            st.session_state.contact_emails = contact_emails
        
        # Return both email data and contact analysis
        return email_data, contact_counter.most_common(10) if contact_counter else None
        
    except Exception as e:
        st.sidebar.error(f"Error fetching emails: {str(e)}")
        import traceback
        st.sidebar.text(traceback.format_exc())
        return None, None

# Function to analyze relationships with a specific contact
def analyze_relationship(service, contact_email, contact_name, user_email, max_emails=50):
    """
    Analyze the relationship between the user and a specific contact
    based on their email communications.
    """
    try:
        # Fetch both incoming and outgoing emails with this contact
        incoming_query = f"from:{contact_email}"
        outgoing_query = f"to:{contact_email}"
        
        # Get emails from this contact
        incoming_results = service.users().messages().list(
            userId="me", 
            maxResults=max_emails // 2,
            q=incoming_query
        ).execute()
        
        # Get emails to this contact
        outgoing_results = service.users().messages().list(
            userId="me", 
            maxResults=max_emails // 2,
            q=outgoing_query
        ).execute()
        
        incoming_messages = incoming_results.get("messages", [])
        outgoing_messages = outgoing_results.get("messages", [])
        
        # Process the messages to extract content
        communication_data = []
        
        # Process incoming messages
        with st.spinner(f"Analyzing {len(incoming_messages) + len(outgoing_messages)} emails with {contact_name}..."):
            # Process incoming messages
            for i, msg in enumerate(incoming_messages):
                progress = (i + 1) / (len(incoming_messages) + len(outgoing_messages))
                st.progress(progress, text=f"Processing emails... {i+1}/{len(incoming_messages) + len(outgoing_messages)}")
                
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                snippet = msg_detail.get("snippet", "")
                
                # Get the body content if available
                body = ""
                try:
                    if "parts" in msg_detail.get("payload", {}):
                        for part in msg_detail["payload"]["parts"]:
                            if part["mimeType"] == "text/plain":
                                if "data" in part["body"]:
                                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                                break
                    elif "body" in msg_detail.get("payload", {}) and "data" in msg_detail["payload"]["body"]:
                        body = base64.urlsafe_b64decode(msg_detail["payload"]["body"]["data"]).decode("utf-8")
                except Exception as e:
                    body = f"[Error extracting body: {str(e)}]"
                
                communication_data.append({
                    "direction": "incoming",
                    "subject": subject,
                    "date": date,
                    "snippet": snippet,
                    "body": body
                })
            
            # Process outgoing messages
            for i, msg in enumerate(outgoing_messages):
                progress = (i + len(incoming_messages) + 1) / (len(incoming_messages) + len(outgoing_messages))
                st.progress(progress, text=f"Processing emails... {i+len(incoming_messages)+1}/{len(incoming_messages) + len(outgoing_messages)}")
                
                msg_detail = service.users().messages().get(userId="me", id=msg["id"]).execute()
                headers = msg_detail.get("payload", {}).get("headers", [])
                
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
                date = next((h["value"] for h in headers if h["name"] == "Date"), "")
                snippet = msg_detail.get("snippet", "")
                
                # Get the body content if available
                body = ""
                try:
                    if "parts" in msg_detail.get("payload", {}):
                        for part in msg_detail["payload"]["parts"]:
                            if part["mimeType"] == "text/plain":
                                if "data" in part["body"]:
                                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
                                break
                    elif "body" in msg_detail.get("payload", {}) and "data" in msg_detail["payload"]["body"]:
                        body = base64.urlsafe_b64decode(msg_detail["payload"]["body"]["data"]).decode("utf-8")
                except Exception as e:
                    body = f"[Error extracting body: {str(e)}]"
                
                communication_data.append({
                    "direction": "outgoing",
                    "subject": subject,
                    "date": date,
                    "snippet": snippet,
                    "body": body
                })
        
        if not communication_data:
            return "No email communications found with this contact."
        
        # Format the data for analysis
        formatted_data = format_communication_data(communication_data, contact_name)
        
        # Analyze the relationship using OpenAI
        with st.spinner("AI analyzing relationship patterns..."):
            analysis = analyze_communication_with_ai(formatted_data, contact_name)
        
        return analysis
        
    except Exception as e:
        import traceback
        st.error(f"Error analyzing relationship: {str(e)}")
        st.text(traceback.format_exc())
        return f"Error analyzing relationship: {str(e)}"

def format_communication_data(communication_data, contact_name):
    """Format the communication data for AI analysis"""
    formatted = f"Communications with {contact_name}:\n\n"
    
    # Sort by date
    communication_data.sort(key=lambda x: parse_date(x["date"]))
    
    # Format each message
    for comm in communication_data:
        formatted += f"Direction: {comm['direction'].upper()}\n"
        formatted += f"Date: {comm['date']}\n"
        formatted += f"Subject: {comm['subject']}\n"
        formatted += f"Content: {comm['snippet']}\n"
        if comm.get('body'):
            # Include a short excerpt of the body to avoid token limits
            body_excerpt = comm['body'][:300]
            formatted += f"Body Excerpt: {body_excerpt}...\n"
        formatted += "\n---\n\n"
    
    return formatted

def analyze_communication_with_ai(formatted_data, contact_name):
    """Send the communication data to OpenAI for relationship analysis"""
    system_message = f"""You are a relationship analyzer AI that examines email communications between people.
    Analyze the provided emails between the user and {contact_name} to determine:
    
    1. The relationship type (colleague, client, friend, vendor, etc.)
    2. Overall sentiment and tone (formal, friendly, collaborative, tense, etc.)
    3. Common topics discussed
    4. Communication patterns (who initiates more often, response styles, response times if detectable)
    5. Any notable observations about the relationship
    
    Format your response in clear sections with these headings, and provide specific examples from the emails to support your analysis.
    """
    
    try:
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"Please analyze these communications:\n\n{formatted_data}"}
        ]
        
        response = client.chat.completions.create(
            model="gpt-3.5-turbo-16k",  # Using a larger context model
            messages=messages,
            temperature=0.4,
            max_tokens=1000
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Analysis error: {str(e)}"

# Function to get contact email from name
def get_contact_email(contact_name):
    if "contact_emails" in st.session_state and contact_name in st.session_state.contact_emails:
        return st.session_state.contact_emails[contact_name]
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

# Function to handle Slack OAuth token exchange
def exchange_slack_code_for_token(auth_code):
    try:
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
        
        try:
            token_data = response.json()
            
            # Debug token data (safely without exposing sensitive info)
            st.sidebar.write("Response JSON parsed successfully")
            st.sidebar.write("Response contains 'ok':", "ok" in token_data)
            st.sidebar.write("Response has access_token:", "access_token" in token_data)
            
            if not token_data.get("ok", False):
                error_msg = token_data.get("error", "Unknown error")
                st.error(f"⚠️ Slack authentication error: {error_msg}")
                st.write("Full error response:")
                st.json(token_data)
                return False
            else:
                # Extract values with safe defaults
                access_token = token_data.get("access_token")
                team_info = token_data.get("team", {})
                user_info = token_data.get("authed_user", {})
                
                if not access_token:
                    st.error("No access token received from Slack")
                    return False
                else:
                    # Store token info
                    st.session_state["slack_credentials"] = {
                        "access_token": access_token,
                        "team_name": team_info.get("name", "Unknown Workspace") if team_info else "Unknown Workspace",
                        "user_id": user_info.get("id") if user_info else None
                    }
                    st.success("✅ Slack connected successfully!")
                    return True
        except Exception as json_error:
            st.error(f"Failed to parse JSON response: {str(json_error)}")
            st.write("Raw response text (first 500 chars):")
            st.code(response.text[:500])
            return False
            
    except Exception as e:
        st.error(f"⚠️ Slack authentication error: {str(e)}")
        import traceback
        st.code(traceback.format_exc())
        return False

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

# This will run once when Gmail is first connected to perform the analysis
def display_top_contacts():
    if "gmail_credentials" in st.session_state and "top_contacts_analyzed" not in st.session_state:
        st.session_state.top_contacts_analyzed = True
        
        with st.spinner("Analyzing your email contacts..."):
            _, top_contacts = get_email_data(max_emails=500, analyze_contacts=True)
        
        if top_contacts:
            st.session_state.top_contacts = top_contacts
        else:
            st.session_state.top_contacts = []
    
    # Display top contacts if available
    if "top_contacts" in st.session_state and st.session_state.top_contacts:
        st.subheader("📊 Your Top Email Contacts")
        
        # Create columns for visualization
        chart_col, list_col = st.columns([3, 2])
        
        with chart_col:
            # Prepare data for the chart using Streamlit's native chart
            import pandas as pd
            
            # Convert to DataFrame for easier charting
            chart_data = pd.DataFrame({
                "Contact": [contact[0][:20] + "..." if len(contact[0]) > 20 else contact[0] for contact in st.session_state.top_contacts],
                "Emails": [contact[1] for contact in st.session_state.top_contacts]
            })
            
            # Sort the data for proper display
            chart_data = chart_data.sort_values("Emails", ascending=True)
            
            # Use Streamlit's native bar chart
            st.bar_chart(chart_data.set_index("Contact"))
        
        with list_col:
            # Display as a list with counts
            st.write("### Top Contacts")
            for i, (contact, count) in enumerate(st.session_state.top_contacts, 1):
                st.write(f"**{i}. {contact}** - {count} emails")


# Check for authorization code in query parameters (OAuth callback)
if "code" in st.query_params:
    # Determine which service this is for based on state parameter
    if "state" in st.query_params and st.query_params["state"].startswith("slack_"):
        # This is Slack OAuth callback
        auth_code = st.query_params["code"]
        # Process the code
        exchange_slack_code_for_token(auth_code)
        # Clear query parameters
        st.query_params.clear()
        st.rerun()
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
tabs = st.tabs(["Chat", "Communications", "Relationships", "Settings"])

# Display top contacts if Gmail is connected
if "gmail_credentials" in st.session_state:
    display_top_contacts()

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
        email_data, _ = get_email_data() if "gmail_credentials" in st.session_state else (None, None)
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
            try:
                email_data, _ = get_email_data()
                
                if email_data is None or len(email_data) == 0:
                    st.info("No unread emails found.")
                else:
                    for i, email in enumerate(email_data, 1):
                        # Check if email is a dictionary and has necessary fields
                        if isinstance(email, dict):
                            # Use a safer approach for the expander title
                            email_subject = email.get('subject', 'No Subject')
                            with st.expander(f"📩 {email_subject}"):
                                st.write(f"**From:** {email.get('sender', 'Unknown Sender')}")
                                st.write(f"**Date:** {email.get('date', 'No Date')}")
                                st.write("**Preview:**")
                                st.write(email.get('snippet', 'No preview available'))
                        else:
                            # Handle case where email is not properly structured
                            st.warning(f"Email #{i} has an invalid format")
            except Exception as e:
                st.error(f"Error loading emails: {str(e)}")
                st.info("Please try refreshing the page or reconnecting your Gmail account.")
    
    with comm_tabs[1]:  # Slack tab
        st.subheader("💬 Recent Slack Messages")
        
        # Check if slack is connected
        if "slack_credentials" not in st.session_state:
            # Slack connection section
            st.info("Connect your Slack account to access your messages")
            
            # Generate Slack authorization URL with persistent state parameter
            persistent_state = f"slack_{st.session_state.persistent_slack_state}"
            
            # Simpler URL construction
            auth_url = (
                f"https://slack.com/oauth/v2/authorize"
                f"?client_id={SLACK_CLIENT_ID}"
                f"&user_scope=channels:history,channels:read,groups:history,groups:read,users:read"
                f"&redirect_uri={SLACK_REDIRECT_URI}"
                f"&state={persistent_state}"
            )
            
            # Display regular markdown link (will open in new window)
            st.markdown(f"🔗 [Connect Slack (opens in new window)]({auth_url})")
            
            # Show a better manual connection option
            with st.expander("Manual Connection Option (if automatic doesn't work)", expanded=True):
                st.write("""
                ### Instructions
                1. Click the link above to start the Slack authorization
                2. After approving, Slack will redirect you back
                3. If you get redirected to a different window and the connection fails, copy the 'code' parameter from the URL
                4. Paste the code below and click 'Submit Code'
                
                Example: If you are redirected to a URL like:
                https://i4gbxwyduex7sferh9ktbc.streamlit.app/?code=12345&state=slack_abcdef
                
                Then the code you need is: 12345
                """)
                
                # Manual code entry
                manual_code = st.text_input("Enter the authorization code from Slack:", key="manual_slack_code")
                
                if st.button("Submit Code"):
                    if manual_code:
                        success = exchange_slack_code_for_token(manual_code)
                        if success:
                            st.rerun()
                    else:
                        st.error("Please enter a valid code")
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

with tabs[2]:  # Relationships tab
    st.subheader("🤝 Relationship Insights")
    
    if "gmail_credentials" not in st.session_state:
        st.info("Connect your Gmail account to view relationship insights")
    else:
        # Get top contacts for analysis
        if "top_contacts" not in st.session_state:
            # Trigger the analysis if not already done
            with st.spinner("Analyzing your email contacts..."):
                _, top_contacts = get_email_data(max_emails=500, analyze_contacts=True)
                if top_contacts:
                    st.session_state.top_contacts = top_contacts
        
        if "top_contacts" in st.session_state and st.session_state.top_contacts:
            # Display a selector for contacts
            contact_options = [contact[0] for contact in st.session_state.top_contacts]
            selected_contact = st.selectbox("Select a contact to analyze your relationship:", contact_options)
            
            if selected_contact:
                # Get contact email (you'll need to store email addresses with contact names)
                contact_email = get_contact_email(selected_contact)
                
                if contact_email:
                    if st.button("Analyze Relationship") or ("current_relationship_analysis" in st.session_state and st.session_state.current_contact == selected_contact):
                        # Recreate service
                        creds_dict = st.session_state["gmail_credentials"]
                        credentials = Credentials(
                            token=creds_dict["token"],
                            refresh_token=creds_dict.get("refresh_token"),
                            token_uri=creds_dict["token_uri"],
                            client_id=creds_dict["client_id"],
                            client_secret=creds_dict["client_secret"],
                            scopes=creds_dict["scopes"]
                        )
                        service = build("gmail", "v1", credentials=credentials)
                        
                        # Get user email
                        user_email = get_user_email_address(service)
                        
                        # Run the analysis if not cached or contact changed
                        if "current_relationship_analysis" not in st.session_state or st.session_state.current_contact != selected_contact:
                            relationship_analysis = analyze_relationship(service, contact_email, selected_contact, user_email)
                            st.session_state.current_relationship_analysis = relationship_analysis
                            st.session_state.current_contact = selected_contact
                        
                        # Display the analysis
                        st.markdown(st.session_state.current_relationship_analysis)
                else:
                    st.warning(f"Could not find email address for {selected_contact}. Please try another contact.")
        else:
            st.info("No contact data available. Please ensure your Gmail account is connected and try refreshing the page.")

with tabs[3]:  # Settings tab
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
                # Also clear any analysis based on Gmail
                if "top_contacts" in st.session_state:
                    del st.session_state["top_contacts"]
                if "top_contacts_analyzed" in st.session_state:
                    del st.session_state["top_contacts_analyzed"]
                if "current_relationship_analysis" in st.session_state:
                    del st.session_state["current_relationship_analysis"]
                if "current_contact" in st.session_state:
                    del st.session_state["current_contact"]
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
            
            # Generate Slack authorization URL with persistent state
            persistent_state = f"slack_{st.session_state.persistent_slack_state}"
            
            # Simpler URL construction
            auth_url = (
                f"https://slack.com/oauth/v2/authorize"
                f"?client_id={SLACK_CLIENT_ID}"
                f"&user_scope=channels:history,channels:read,groups:history,groups:read,users:read"
                f"&redirect_uri={SLACK_REDIRECT_URI}"
                f"&state={persistent_state}"
            )
            
            # Display connect button
            st.markdown(f"🔗 [Connect Slack (opens in new window)]({auth_url})")
            
            # Show manual connection option
            with st.expander("Manual Connection Option", expanded=False):
                st.write("If automatic connection fails, enter the authorization code from Slack:")
                manual_code = st.text_input("Slack authorization code:", key="settings_slack_code")
                if st.button("Submit Code", key="settings_submit_code"):
                    if manual_code:
                        success = exchange_slack_code_for_token(manual_code)
                        if success:
                            st.rerun()
                    else:
                        st.error("Please enter a valid code")
    
    st.write("---")
    
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
    - Analyze your relationships with contacts
    
    Version: 1.1
    """)
