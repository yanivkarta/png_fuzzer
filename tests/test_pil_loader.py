import unittest
import os
import sys
import subprocess
from PIL import Image
import io

# Add the directory containing pil_loader.py to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import pil_loader

class TestPilLoader(unittest.TestCase):

    def setUp(self):
        self.test_dir = "test_temp_pil_loader"
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_image_path = os.path.join(self.test_dir, "test_image.png")
        self.create_dummy_png(self.test_image_path)

    def tearDown(self):
        if os.path.exists(self.test_image_path):
            os.remove(self.test_image_path)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)

    def create_dummy_png(self, path):
        """Creates a simple 10x10 black PNG image."""
        img = Image.new('RGB', (10, 10), color = 'black')
        img.save(path)

    def test_load_and_process_image_success(self):
        """Test that a valid image is processed successfully."""
        exit_code = pil_loader.load_and_process_image(self.test_image_path)
        self.assertEqual(exit_code, 0, "Should return 0 for successful image processing")

    def test_load_and_process_image_file_not_found(self):
        """Test handling of a non-existent image file."""
        non_existent_path = os.path.join(self.test_dir, "non_existent.png")
        exit_code = pil_loader.load_and_process_image(non_existent_path)
        self.assertEqual(exit_code, 1, "Should return 1 for FileNotFoundError")

    def test_load_and_process_image_invalid_file(self):
        """Test handling of an invalid image file (e.g., a text file)."""
        invalid_image_path = os.path.join(self.test_dir, "invalid_image.txt")
        with open(invalid_image_path, "w") as f:
            f.write("This is not an image file.")
        
        exit_code = pil_loader.load_and_process_image(invalid_image_path)
        self.assertEqual(exit_code, 1, "Should return 1 for invalid image file")
        os.remove(invalid_image_path)

    def test_main_script_success(self):
        """Test the main execution path of pil_loader.py with a valid image."""
        script_path = os.path.abspath("pil_loader.py")
        result = subprocess.run([sys.executable, script_path, self.test_image_path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Script should exit with 0. Stderr: {result.stderr}")
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")

    def test_main_script_no_arguments(self):
        """Test the main execution path of pil_loader.py with no arguments."""
        script_path = os.path.abspath("pil_loader.py")
        result = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, "Script should exit with 1 for no arguments")
        self.assertIn("Usage: python pil_loader.py <image_path>", result.stderr)

    def test_main_script_file_not_found(self):
        """Test the main execution path of pil_loader.py with a non-existent file."""
        script_path = os.path.abspath("pil_loader.py")
        non_existent_path = os.path.join(self.test_dir, "non_existent_main.png")
        result = subprocess.run([sys.executable, script_path, non_existent_path], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, "Script should exit with 1 for FileNotFoundError")
        self.assertIn("Error: Image file not found", result.stderr)

if __name__ == '__main__':
    unittest.main()
