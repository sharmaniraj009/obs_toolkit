import base64
# import deobfuscate
from deobfuscate import deobfuscate


def test_base64_deobfuscate():
    input_text = "Lets Obfuscate this text"
    deobfuscated_text = base64.b64encode(input_text.encode()).decode()
    assert deobfuscate.process(input_text) == deobfuscated_text