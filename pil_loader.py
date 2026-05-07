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
        
        print(f"Image loaded successfully: {image_path}", file=sys.stdout)

        # Resize to 256x256
        img = img.resize((256, 256))
        print("Image resized to 256x256.", file=sys.stdout)

        # Convert to RGB
        img = img.convert("RGB")
        print("Image converted to RGB.", file=sys.stdout)
        
        # If we reach here, processing was successful
        print("Image processed successfully.", file=sys.stdout)
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
    #generate stdout and stderr output to simulate viewer behavior and potential leaks 
    print(f"Processing image: {image_path}", file=sys.stdout)

    exit_code = load_and_process_image(image_path)
    if exit_code == 0:
        print("Image processed successfully.", file=sys.stdout)
    else:        
        print("Image processing failed.", file=sys.stderr)

    sys.exit(exit_code)
