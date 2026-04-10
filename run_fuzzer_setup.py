import os
import shutil
import subprocess
import zlib # Needed for calculate_png_crc
import torch
from torch.utils.tensorboard import SummaryWriter
from ml_fuzzer_model import AddressOracle, AddressSample, AddressDataset, train_address_oracle

# PNG IEND chunk marker (hex: 49 45 4e 44 ae 42 60 82)
IEND_CHUNK = b'\x49\x45\x4e\x44\xae\x42\x60\x82'

def calculate_png_crc(chunk_type: bytes, data: bytes) -> bytes:
    """Calculates the CRC-32 for a PNG chunk."""
    return zlib.crc32(chunk_type + data).to_bytes(4, 'big')

def generate_base_png(output_path: str, width: int = 100, height: int = 100):
    """Generates a valid PNG file with multiple chunks for better fuzzing coverage."""
    signature = b'\x89PNG\r\n\x1a\n'
    
    ihdr_type = b'IHDR'
    ihdr_data = (
        width.to_bytes(4, 'big') +
        height.to_bytes(4, 'big') +
        b'\x08' + # Bit depth
        b'\x03' + # Color type (Indexed-color)
        b'\x00' + # Compression method
        b'\x00' + # Filter method
        b'\x00'   # Interlace method
    )
    ihdr_chunk = len(ihdr_data).to_bytes(4, 'big') + ihdr_type + ihdr_data + calculate_png_crc(ihdr_type, ihdr_data)
    
    plte_type = b'PLTE'
    plte_data = b'\xff\x00\x00' + b'\x00\xff\x00' + b'\x00\x00\xff'
    plte_chunk = len(plte_data).to_bytes(4, 'big') + plte_type + plte_data + calculate_png_crc(plte_type, plte_data)
    
    idat_type = b'IDAT'
    raw_data = b'\x00' + (b'\x00' * width)
    full_raw_data = raw_data * height
    compressed_data = zlib.compress(full_raw_data)
    idat_chunk = len(compressed_data).to_bytes(4, 'big') + idat_type + compressed_data + calculate_png_crc(idat_type, compressed_data)
    
    iend_chunk = b'\x00\x00\x00\x00' + IEND_CHUNK
    
    with open(output_path, 'wb') as f:
        f.write(signature + ihdr_chunk + plte_chunk + idat_chunk + iend_chunk)

# Setup test environment
test_data_dir = "test_data_dir_fuzzer"
os.makedirs(test_data_dir, exist_ok=True)

# Create infect_test.png
infect_test_png_path = os.path.join(test_data_dir, "infect_test.png")
generate_base_png(infect_test_png_path)
print(f"Created {infect_test_png_path}")

# Copy png_consumer
if os.path.exists("./png_consumer"):
    shutil.copy("./png_consumer", test_data_dir)
    print(f"Copied png_consumer to {test_data_dir}")
else:
    print("WARNING: png_consumer not found in current directory. Fuzzer might fail for png_consumer viewer.")

# Create a dummy fuzzing_trajectory.csv for training data
dummy_csv_content = """
timestamp,original_file,viewer,fuzz_type,payload_offset_attempted,status,reason,retry_attempt,trigger_offset_attempted
1678886400,infect_test.png,eog,uaf,100,CRASHED,segfault,0,0
1678886401,infect_test.png,firefox,overflow,200,SUCCESS,,0,0
1678886402,infect_test.png,eog,metadata_trigger,50,FAILED,timeout,0,0
"""
with open(os.path.join(test_data_dir, "fuzzing_trajectory.csv"), "w") as f:
    f.write(dummy_csv_content)
print(f"Created dummy fuzzing_trajectory.csv in {test_data_dir}")

# Run the fuzzer for intelligent mode training
python_executable = os.path.expanduser("~/nvenv/bin/python3")

print("\n--- Skipping fuzzer training for demo, going to AddressOracle ---")

# Train AddressOracle with dummy data for demonstration
print("\n--- Training AddressOracle ---")
dummy_address_samples = [
    AddressSample(
        features=[1000.0, 1600000000.0, 1.0, 0.5, 1000000, 2000000] + [0.0]*50 + [1, 0],  # features
        addresses=[0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080]  # smaller dummy addresses
    ),
    AddressSample(
        features=[1200.0, 1600001000.0, 2.0, 1.0, 1500000, 2500000] + [0.1]*50 + [0, 1],
        addresses=[0x2000, 0x2010, 0x2020, 0x2030, 0x2040, 0x2050, 0x2060, 0x2070, 0x2080]
    )
]
address_dataset = AddressDataset(dummy_address_samples)
oracle = AddressOracle(address_dataset.input_dim, address_dataset.output_dim)
device = "cuda" if torch.cuda.is_available() else "cpu"
writer = SummaryWriter("runs/address_oracle_training")
accuracy = train_address_oracle(oracle, address_dataset, epochs=100, device=device, writer=writer)
print(f"AddressOracle trained with accuracy: {accuracy:.4f}")
if accuracy > 0.95:
    torch.save(oracle.state_dict(), "models/address_oracle.pth")
    print("AddressOracle model saved.")
else:
    print("AddressOracle accuracy below threshold, not saving.")
writer.close()

# Clean up test data directory after all runs
if os.path.exists(test_data_dir):
    shutil.rmtree(test_data_dir)
    print(f"\nCleaned up test data directory: {test_data_dir}")
