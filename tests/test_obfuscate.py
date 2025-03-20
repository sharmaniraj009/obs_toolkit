import base64
from obfuscate import obfuscate

def test_base64_obfuscate():
    input_text = "Lets Obfuscate this text"
    obfuscated_text = base64.b64encode(input_text.encode()).decode()
    assert obfuscate.process(input_text) == obfuscated_text