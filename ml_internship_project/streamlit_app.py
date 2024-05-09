import streamlit as st
from io import BytesIO
from PyPDF2 import PdfReader
from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
from langchain_community.vectorstores.chroma import Chroma
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
import re
from dotenv import load_dotenv, find_dotenv
from typing import Tuple, Optional, List

# __import__('pysqlite3')
# import sys
# sys.modules['sqlite3'] = sys.modules.pop('pysqlite3')

_ : bool = load_dotenv(find_dotenv())

CHROMA_PATH = "Persist_dir"

def detect_sensitive_information(text: str) -> list[str]:
    '''
    Detects and return the sensitive information present in the text provided

    Parameters:
        text (str): Input may containing the sensitive information

    Returns:
        sensitive_info list[str]: Returns array containing the email, phone or credit card if present in input
    '''
    sensitive_info = []

    # Regular expressions for detecting sensitive information
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    phone_pattern = r'\b(?:\d{3}[-.\s]?)?\d{3}[-.\s]?\d{4}\b'
    credit_card_pattern = r'\b(?:\d[ -]*?){13,16}\b'

    # Checks for the email pattern in the text provided
    if emails := re.findall(email_pattern, text):
        sensitive_info.extend(emails)

    # Check for the phone pattern in the text provided
    if phones := re.findall(phone_pattern, text):
        sensitive_info.extend(phones)

    # Check for the credit card pattern in the text provided
    if credit_cards := re.findall(credit_card_pattern, text):
        sensitive_info.extend(credit_cards)

    # Return the data detected using the above regex expression
    return sensitive_info

def contains_inappropriate_content(text: str) -> bool:
    '''
    Detects the inappropriate content present in the text provided

    Parameters:
        text (str): Input may containing the inappropriate content

    Returns:
        bool: Returns True or False if censored word present in the text provided
    '''
    # List of censored words
    censored_words = ["fuck", "shit", "damn", "ass", "bitch", "bastard", "nigga"]

    # Check if any censored word is present in the text
    return any(word in text.split() for word in censored_words)

def split_text(documents: list[str]) -> list[Document]:
    """
    Splits a list of documents into chunks of text.

    Parameters:
    - documents (list[str]): A list of strings representing the documents to be split.

    Returns:
    - chunks (list[Document]): A list of strings where each string represents a chunk of text extracted from the documents.
    """
    # Initialize a RecursiveCharacterTextSplitter object with specific parameters for chunking text
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=300,  # Define the size of each chunk of text
        chunk_overlap=100,  # Define the amount of overlap between consecutive chunks
        length_function=len,  # Specify the function used to determine the length of the text
        add_start_index=True,  # Specify whether to include the starting index of each chunk
    )
    
    # Use the text_splitter to split the documents into chunks
    return text_splitter.split_documents([Document(page_content=doc) for doc in documents])
    

def get_similar_docs(question: str, Vector_db: Chroma, similar_doc_count: Optional[int] = 3) -> List[Tuple[Document, float]]:
    """
    Gets a list of unique documents based on the similarity search results.

    Args:
        question (str): The question used for similarity search.
        Vector_db: The vector database used for similarity search.
        similar_doc_count (int): The number of similar documents to retrieve.

    Returns:
        list: A list of unique documents based on the similarity search results.
    """
    # Extract the similar documents based on similarity search using user query
    similar_docs = Vector_db.similarity_search_with_relevance_scores(question, similar_doc_count)

    # Initialize empty list to store the unique documents extracted from the database
    unique_docs = []
    seen_doc_contents = set()

    # Extract the unique document and keep track of the documents already extracted previously
    for doc, score in similar_docs:
        doc_content = doc.page_content
        if doc_content not in seen_doc_contents:
            unique_docs.append((doc, score))
            seen_doc_contents.add(doc_content)

    # Return the extracted unique documents
    return unique_docs

# Setup the app title
st.title('Ask Research AI')

# Interface for uploading documents
pdf_files = st.file_uploader("Upload PDF files", accept_multiple_files=True)

# Global variable defined for Vector_db
Vector_db = None

if pdf_files:
    # Process uploaded documents
    all_documents = []
    for pdf_file in pdf_files:
        # Read PDF file as bytes
        pdf_bytes = pdf_file.read()

        # Create a BytesIO object
        pdf_stream = BytesIO(pdf_bytes)

        # Use PyPDF2 to extract text from PDF
        pdf_reader = PdfReader(pdf_stream)
        text = "".join(
            pdf_reader.pages[page_num].extract_text()
            for page_num in range(len(pdf_reader.pages))
        )
        # Append extracted text to the list of all documents
        all_documents.append(text)

    # Divide the documents into chunks
    chunks = split_text(all_documents)
    
    # Convert chunks into embeddings and store them in Vector Database
    Vector_db: Chroma = Chroma.from_documents(collection_name="document_docs", 
                                              documents=chunks, 
                                              embedding=OpenAIEmbeddings(model="text-embedding-3-small"), 
                                              persist_directory=CHROMA_PATH)
    
    # Explicitly persist the data to the disk
    Vector_db.persist()


PROMPT_TEMPLATE = """  
Instruction:
Use the below context to answer the user question with the best response possible.
Explain the answer with reference to these context.
If you don't have the information in below context then give response "Required information is not provided in the context".

Context: {context}

Question: {question}

Response:
"""

# Setup a session state message variable to hold all the old messages
if 'messages' not in st.session_state:
    st.session_state.messages = []

# Display all the historical messages
for message in st.session_state.messages:
    st.chat_message(message['role']).markdown(message['content'])

if prompt := st.chat_input('Pass Your Prompt here'):
    # Display the prompt
    st.chat_message('user').markdown(prompt)
    st.session_state.messages.append({'role': 'user', 'content':prompt})

    # Check if the prompt contains inappropriate content
    if contains_inappropriate_content(prompt):
        st.warning("Your prompt contains inappropriate content. Please rephrase.")
    elif detect_sensitive_information(prompt):
        st.warning("Your prompt contains sensitive information. Please rewrite.")
    else:
        # Extract the relevant chunks from DB based on user query
        results = get_similar_docs(prompt, Vector_db, 3)

        # Creating prompt using extracted chunks
        context_text = "\n\n---\n\n".join([doc.page_content for doc, _score in results])
        prompt_template = ChatPromptTemplate.from_template(PROMPT_TEMPLATE)

        final_prompt = prompt_template.format(context=context_text, question=prompt)

        # Initializing the model
        model = ChatOpenAI(model="gpt-3.5-turbo-1106")
        
        # Passing prompt to model to get the answer
        print(final_prompt)
        answer = model.invoke(final_prompt)

        # Check if the generated answer contains inappropriate content
        if contains_inappropriate_content(answer.content):
            st.warning("The generated answer contains inappropriate content. Please try again.")
        
        # Check if the generated answer contains the sensitive information
        elif detect_sensitive_information(answer.content):
            st.warning("Your prompt contains sensitive information. Please rewrite.")
        
        # If everything is okay and generated response doesn't contain the inappropriate or sensitive information we could display the answer 
        else:
            st.chat_message('assistant').markdown(answer.content)
            st.session_state.messages.append({
                'role': 'assistant', 
                'content': answer.content
            })