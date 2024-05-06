from langchain.schema import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter

def split_text(documents: list[str]):
    """
    Splits a list of documents into chunks of text.

    Parameters:
    - documents (list[str]): A list of strings representing the documents to be split.

    Returns:
    - chunks (list[str]): A list of strings where each string represents a chunk of text extracted from the documents.
    """
    # Initialize a RecursiveCharacterTextSplitter object with specific parameters for chunking text
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=300,  # Define the size of each chunk of text
        chunk_overlap=100,  # Define the amount of overlap between consecutive chunks
        length_function=len,  # Specify the function used to determine the length of the text
        add_start_index=True,  # Specify whether to include the starting index of each chunk
    )
    
    # Use the text_splitter to split the documents into chunks
    chunks = text_splitter.split_documents([Document(page_content=doc) for doc in documents])
    
    # Return the resulting chunks
    return chunks

text = ['''
This text splitter is the recommended one for generic text. It is parameterized by a list of characters. It tries to split on them in order until the chunks are small enough. The default list of separators is ["\n\n", "\n", " ", ""]. This has the effect of trying to keep all paragraphs (and then sentences, and then words) together as long as possible, as those would generically seem to be the strongest semantically related pieces of text.

How the text is split: by list of characters
How the chunk size is measured: by number of characters
Important parameters to know here are chunkSize and chunkOverlap. chunkSize controls the max size (in terms of number of characters) of the final documents. chunkOverlap specifies how much overlap there should be between chunks. This is often helpful to make sure that the text isn't split weirdly. In the example below we set these values to be small (for illustration purposes), but in practice they default to 1000 and 200 respectively.
''']

result = split_text(text)    
print(result)