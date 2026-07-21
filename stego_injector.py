# filepath: puzzle_kit/stego_injector.py
import os
import hashlib
import zlib
from PIL import Image

def get_pixel_hash(image_path):
    """
    Generate a cryptographic hash of the raw pixel RGB data.
    This binds the decryption key directly to the image pixels.
    Any pixel modification will break decryption.
    """
    img = Image.open(image_path).convert("RGB")
    pixel_bytes = bytes(img.tobytes())
    return hashlib.sha256(pixel_bytes).hexdigest()

def derive_key(pixel_hash):
    """
    Derive an encryption key from the pixel hash.
    """
    return hashlib.sha256(pixel_hash.encode("utf-8")).digest()

def encrypt_payload(payload_bytes, key):
    """
    Symmetric keystream cipher.
    """
    encrypted = bytearray()
    current_state = key
    for i, byte in enumerate(payload_bytes):
        if i % 32 == 0:
            current_state = hashlib.sha256(current_state).digest()
        encrypted.append(byte ^ current_state[i % 32])
    return bytes(encrypted)

def make_chunk(chunk_type, chunk_data):
    """
    Build a standard PNG chunk: [Length: 4B] [Type: 4B] [Data: LB] [CRC: 4B]
    """
    type_bytes = chunk_type.encode("ascii")
    length_bytes = len(chunk_data).to_bytes(4, "big")
    crc = zlib.crc32(type_bytes + chunk_data)
    crc_bytes = crc.to_bytes(4, "big")
    return length_bytes + type_bytes + chunk_data + crc_bytes

def inject_custom_chunk(png_path, chunk_type, chunk_data, output_path):
    """
    Inject a custom ancillary chunk into the PNG after the IHDR chunk.
    This hides raw binary payload in the file structure, invisible to metadata readers.
    """
    with open(png_path, "rb") as f:
        png_data = f.read()
        
    if png_data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Not a valid PNG file.")
        
    # Find IHDR end
    ihdr_len = int.from_bytes(png_data[8:12], "big")
    ihdr_end = 8 + 4 + 4 + ihdr_len + 4
    
    custom_chunk = make_chunk(chunk_type, chunk_data)
    new_png_data = png_data[:ihdr_end] + custom_chunk + png_data[ihdr_end:]
    
    with open(output_path, "wb") as f:
        f.write(new_png_data)
    print(f"[+] Custom chunk '{chunk_type}' injected successfully into {output_path}")

def extract_custom_chunk(png_path, chunk_type):
    """
    Locate and extract a custom ancillary chunk from the PNG file bytes.
    """
    with open(png_path, "rb") as f:
        png_data = f.read()
        
    type_bytes = chunk_type.encode("ascii")
    offset = 8
    
    while offset < len(png_data):
        if offset + 8 > len(png_data):
            break
        length = int.from_bytes(png_data[offset:offset+4], "big")
        ctype = png_data[offset+4:offset+8]
        
        if ctype == type_bytes:
            # Found chunk
            data_start = offset + 8
            data_end = data_start + length
            return png_data[data_start:data_end]
            
        offset += 8 + length + 4 # [Length:4] + [Type:4] + [Data:L] + [CRC:4]
        
    raise KeyError(f"Chunk '{chunk_type}' not found in PNG.")

if __name__ == "__main__":
    print("[*] Running Custom Chunk Stego Self-Test...")
    dummy_img = Image.new("RGB", (100, 100), color=(128, 128, 128))
    dummy_img.save("temp_base.png")
    
    test_msg = b"secret_bytecode_data"
    
    # Key bound to pixels
    pixel_hash = get_pixel_hash("temp_base.png")
    key = derive_key(pixel_hash)
    enc_payload = encrypt_payload(test_msg, key)
    
    # Inject
    inject_custom_chunk("temp_base.png", "eNtR", enc_payload, "temp_stego.png")
    
    # Extract
    extracted_enc = extract_custom_chunk("temp_stego.png", "eNtR")
    
    # Decrypt
    extracted_msg = encrypt_payload(extracted_enc, key)
    
    assert extracted_msg == test_msg, f"Self-test failed: {extracted_msg} vs {test_msg}"
    print("[+] Custom Chunk Stego Self-Test Passed!")
    
    if os.path.exists("temp_base.png"): os.remove("temp_base.png")
    if os.path.exists("temp_stego.png"): os.remove("temp_stego.png")
