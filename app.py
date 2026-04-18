import streamlit as st
import google.generativeai as genai
import json
import tempfile
import os

# --- Configuration ---
# Pulling the API key securely from Streamlit Cloud Secrets
try:
    genai.configure(api_key=st.secrets["GEMINI_API_KEY"])
except Exception as e:
    st.error("API Key not found. Please ensure it is set in Streamlit Secrets.")

st.set_page_config(page_title="ScamShield", page_icon="🛡️", layout="centered")

# --- Custom Styling ---
st.markdown("""
    <style>
    .high-risk { background-color: #fff0ee; border-left: 5px solid #b52a1c; padding: 15px; border-radius: 5px; color: #b52a1c;}
    .med-risk { background-color: #fff8ee; border-left: 5px solid #8a6000; padding: 15px; border-radius: 5px; color: #8a6000;}
    .low-risk { background-color: #eef7ee; border-left: 5px solid #1e6e1e; padding: 15px; border-radius: 5px; color: #1e6e1e;}
    </style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ ScamShield")
st.subheader("Multi-Database Threat Analysis Engine")
st.write("Analyze suspicious texts, emails, or voice messages against known fraud patterns.")

# --- Inputs ---
st.markdown("### 1. Submit Message for Analysis")
input_method = st.radio("Choose Input Method:", ["Text / Email", "Voice Message (Audio)"])

text_input = ""
audio_file = None

if input_method == "Text / Email":
    text_input = st.text_area("Paste the suspicious message here...", height=150)
else:
    audio_file = st.file_uploader("Upload Audio File", type=['mp3', 'wav', 'm4a', 'ogg'])

st.markdown("### 2. Contextual Factors")
q1 = st.radio("Did the message sender initiate contact with you?", ["Yes", "No", "Not Sure"], index=2)
q2 = st.radio("Have you responded to the message sender?", ["Yes", "No", "Not Sure"], index=2)
q3 = st.radio("Has the message sender contacted you more than once?", ["Yes", "No", "Not Sure"], index=2)

# --- Analysis Logic ---
if st.button("▸ RUN SCAM ANALYSIS", type="primary", use_container_width=True):
    if input_method == "Text / Email" and not text_input:
        st.warning("Please enter the text message to analyze.")
    elif input_method == "Voice Message (Audio)" and not audio_file:
        st.warning("Please upload an audio file to analyze.")
    else:
        with st.spinner("Cross-referencing fraud databases and analyzing patterns..."):
            try:
                # 1. Build the prompt instructions
                system_prompt = f"""
                You are an expert scam detection analyst. Analyze the provided message (text or audio).
                Consider these context factors:
                - Sender initiated contact: {q1}
                - User responded: {q2}
                - Sender contacted multiple times: {q3}
                
                Cross-reference with known patterns from FTC Sentinel, FBI IC3, Scamwatch, and BBB Scam Tracker.
                
                You must return your analysis strictly as a JSON object with this exact schema:
                {{
                  "likelihood": "HIGH" or "MEDIUM" or "LOW",
                  "likelihood_score": integer between 0 and 100,
                  "scam_type": "Name of the scam type (or None)",
                  "description": "Detailed explanation of why this is or isn't a scam",
                  "red_flags": ["List", "of", "red", "flags"],
                  "databases_matched": ["List", "of", "relevant", "databases"],
                  "advice": "Clear, actionable advice on what the user should do next",
                  "tips": ["List", "of", "tips", "to", "avoid", "this", "in", "the", "future"]
                }}
                """

                # 2. Configure the Gemini Model to strictly output JSON
                model = genai.GenerativeModel(
                    'gemini-2.5-flash',
                    generation_config={"response_mime_type": "application/json"}
                )

                # 3. Handle data and call AI
                if input_method == "Text / Email":
                    response = model.generate_content([system_prompt, f"MESSAGE TO ANALYZE:\n{text_input}"])
                else:
                    # Save audio to temp file so Gemini can read it
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.mp3') as tmp:
                        tmp.write(audio_file.getvalue())
                        tmp_path = tmp.name
                    
                    uploaded_audio = genai.upload_file(path=tmp_path)
                    response = model.generate_content([system_prompt, uploaded_audio])
                    
                    # Clean up temp files
                    os.remove(tmp_path)
                    genai.delete_file(uploaded_audio.name)

                # 4. Parse the JSON response
                result = json.loads(response.text)

                # --- Render Results ---
                st.markdown("---")
                st.header("Analysis Results")
                
                # Verdict Bar
                if result['likelihood'] == "HIGH":
                    st.markdown(f"<div class='high-risk'><h2>⚠️ HIGH RISK (Score: {result['likelihood_score']}/100)</h2><p><b>Identified as:</b> {result.get('scam_type', 'Unknown Threat')}</p></div>", unsafe_allow_html=True)
                elif result['likelihood'] == "MEDIUM":
                    st.markdown(f"<div class='med-risk'><h2>◈ MODERATE RISK (Score: {result['likelihood_score']}/100)</h2><p><b>Identified as:</b> {result.get('scam_type', 'Potential Threat')}</p></div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='low-risk'><h2>✅ LOW RISK (Score: {result['likelihood_score']}/100)</h2><p>No immediate scam patterns detected.</p></div>", unsafe_allow_html=True)

                # Summary
                st.subheader("Analysis Summary")
                st.info(result['description'])

                # Details Columns
                col1, col2 = st.columns(2)
                with col1:
                    if result.get('red_flags'):
                        st.subheader("⚑ Red Flags Detected")
                        for flag in result['red_flags']:
                            st.markdown(f"- {flag}")
                with col2:
                    if result.get('databases_matched'):
                        st.subheader("◈ Database Matches")
                        for db in result['databases_matched']:
                            st.markdown(f"- ✓ {db}")

                # Advice & Tips
                st.subheader("▸ Recommended Action")
                st.warning(result['advice'])
                
                st.subheader("◉ Scam Recognition Tips")
                for i, tip in enumerate(result.get('tips', [])):
                    st.markdown(f"**{i+1}.** {tip}")

                st.caption("⚠ **Disclaimer:** This analysis reflects known patterns but cannot guarantee identification of all scams. If something feels wrong, trust your instincts and do not engage.")

            except Exception as e:
                st.error(f"An error occurred during analysis: {e}")