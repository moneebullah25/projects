import streamlit as st
from faster_whisper import WhisperModel
import torch
import google.generativeai as genai
from dotenv import load_dotenv, find_dotenv
import os
from transformers import pipeline
from datasets import load_dataset
from st_audiorec import st_audiorec
from pydub import AudioSegment

PREV_CONV = 2

# Load environment variables
_ : bool = load_dotenv(find_dotenv()) 
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

# Configure Google generative AI
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-pro')

# Define model and other necessary objects
model_size = "tiny.en"
speech_to_text_model = WhisperModel(model_size)
synthesiser = pipeline("text-to-speech", "microsoft/speecht5_tts")
embeddings_dataset = load_dataset("Matthijs/cmu-arctic-xvectors", split="validation")
speaker_embedding = torch.tensor(embeddings_dataset[7306]["xvector"]).unsqueeze(0)

def text_to_speech(text):
    speech = synthesiser(text, forward_params={"speaker_embeddings": speaker_embedding})
    output = speech['audio']
    return output, speech["sampling_rate"]

PROMPT = '''
Your task is to answer as short as possible.
Do not give output in markdown. And only give response in plain human like english.

Conversation History: {conv_history}

Question: {question}
'''

history = []

def generate_response(user_text):
    response = model.generate_content(user_text)
    return response.text

st.title("AI Bot Interaction")

def save_audio_to_wav(audio_data, filename):
    # Convert to AudioSegment
    audio = AudioSegment(audio_data)
    # Export as WAV file
    audio.export(filename, format="wav")

def interact_with_bot():
    st.sidebar.subheader("Speak to the AI Bot")
    wav_audio_data = st_audiorec()

    if wav_audio_data is not None:
        global history, PROMPT
        # Save audio to a temporary file
        temp_audio_file = "user_audio.wav"
        save_audio_to_wav(wav_audio_data, temp_audio_file)
        # Transcribe audio
        segments, info = speech_to_text_model.transcribe(temp_audio_file, beam_size=5)
        user_text = ""
        for segment in segments:
            user_text += segment.text
        # print(user_text)

        if len(history) > PREV_CONV:
            history = history[-PREV_CONV:]
        
        
        response_text = generate_response(PROMPT.format(conv_history="".join(f"\nUSER: {user}\nBOT:{bot}" for user, bot in history), question=user_text))
        print("PROMT", PROMPT.format(conv_history="".join(f"\nUSER: {user}\nBOT:{bot}" for user, bot in history), question=user_text), 
              "RESPONSE", response_text)

        history.append((user_text, response_text))

        # Convert the response text to speech
        response_audio, sampling_rate = text_to_speech(response_text)
        st.audio(response_audio, format="audio/wav", sample_rate=sampling_rate)

if __name__ == "__main__":
    interact_with_bot()
