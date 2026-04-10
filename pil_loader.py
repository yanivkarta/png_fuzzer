import sys
from PIL import Image
import io

def load_and_process_image(image_path: str):
    """
    Opens, loads, resizes, converts to RGB, and attempts to process an image.
    This simulates a more realistic viewer interaction without displaying a GUI.
    """
    try:
        # Open the image
        img = Image.open(image_path)
        
        # Load the image data
        img.load()
        
        # Resize to 256x256
        img = img.resize((256, 256))
        
        # Convert to RGB
        img = img.convert("RGB")
        
        # Attempt to save to a BytesIO object to simulate processing/rendering
        # without actually writing to disk or opening a GUI.
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format="PNG")
        img_byte_arr.seek(0) # Reset stream position if needed later, though not strictly necessary here.
        
        # If we reach here, processing was successful
        return 0 # Success
    except FileNotFoundError:
        print(f"Error: Image file not found at {image_path}", file=sys.stderr)
        return 1 # Failure
    except Exception as e:
        print(f"Error processing image {image_path}: {e}", file=sys.stderr)
        return 1 # Failure

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pil_loader.py <image_path>", file=sys.stderr)
        sys.exit(1)
    
    image_path = sys.argv[1]
    exit_code = load_and_process_image(image_path)
    sys.exit(exit_code)
