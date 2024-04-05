# to speech conversion 
from gtts import gTTS 

# This module is imported so that we can  
# play the converted audio 
import os 


filepath = 'Mein Kampf Stalag.txt'
text = ''
with open(filepath) as fp:
    line = fp.readline()
    while line:
        text += line.strip() + '\n'
        line = fp.readline()

# Language in which you want to convert 
language = 'en'

# Passing the text and language to the engine,  
# here we have marked slow=False. Which tells  
# the module that the converted audio should  
# have a high speed 
myobj = gTTS(text=text, lang=language, slow=False) 

# Saving the converted audio in a mp3 file named 
# welcome  
myobj.save("Mein Kampf Stalag.mp3") 