
import streamlit as st
import openai

st.set_page_config(page_title="G – Your AI Assistant")

st.title("G – Your AI Assistant")

user_input = st.text_input("Talk to G:", "")

if user_input:
    st.write("G says:")
    st.write("This is a placeholder response from G based on your input: " + user_input)
