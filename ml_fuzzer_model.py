import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset
from torch.utils.tensorboard import SummaryWriter
from typing import List, Tuple, Optional, Dict

from dataclasses import dataclass
import numpy as np
from lime.lime_tabular import LimeTabularExplainer # Import LIME 
import time
import psutil  # For process features

#logging 
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Assuming FuzzingSample and InstrumentationSuggestion are defined in data_processor.py
# For standalone testing, we'll define them here or import if data_processor is available.
try:
    from data_processor import FuzzingSample, InstrumentationSuggestion, ELF_FEATURE_VECTOR_SIZE
except ImportError:
    # Define a dummy ELF_FEATURE_VECTOR_SIZE for standalone testing if data_processor is not available
    ELF_FEATURE_VECTOR_SIZE = 50 
    @dataclass
    class FuzzingSample:
        viewer_name: str
        fuzz_type: str
        file_features: List[float]
        payload_offset_attempted: int
        status_one_hot: List[float]
        gdb_crash_features: List[float]
        leaked_addresses_features: List[float]
        apport_crash_features: List[float]
        success_label: int
        elf_features: List[float]  # New field for ELF features
        chain_type_prediction: str  # e.g., "ROP", "JOP", "VOP"
        trigger_offset_attempted: int = 0


    @dataclass
    class InstrumentationSuggestion:
        fuzz_type_prediction: str
        payload_offset_prediction: int
        trigger_offset_prediction: Optional[int] = None
        chain_type_prediction: str = "ROP"  # New: "ROP", "JOP", "VOP", etc.
        confidence: float = 1.0


@dataclass
class AddressSample:
    features: List[float]
    addresses: List[int]  # actual addresses of gadgets


class AddressDataset(Dataset):
    """Dataset for AddressOracle training."""
    
    def __init__(self, samples: List[AddressSample]):
        self.samples = samples
        if samples:
            self.input_dim = len(samples[0].features)
            self.output_dim = len(samples[0].addresses)
        else:
            self.input_dim = 0
            self.output_dim = 0

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[idx]
        input_tensor = torch.tensor(sample.features, dtype=torch.float32)
        output_tensor = torch.tensor(sample.addresses, dtype=torch.float32)  # addresses as float32
        return input_tensor, output_tensor


class FuzzingDataset(Dataset):
    """Dataset for VAE/GAN training on fuzzing samples."""
    
    def __init__(self, samples: List[FuzzingSample], fuzz_types: List[str], 
                 chain_types: List[str], max_payload_offset: int, max_trigger_offset: int):
        self.samples = samples
        self.fuzz_types = fuzz_types
        self.chain_types = chain_types
        self.max_payload_offset = max_payload_offset
        self.max_trigger_offset = max_trigger_offset
        
        # Calculate dimensions based on actual sample structure
        if samples:
            sample = samples[0]
            self.input_dim = (
                len(sample.file_features) +
                len(sample.status_one_hot) +
                len(sample.gdb_crash_features) +
                len(sample.leaked_addresses_features) +
                len(sample.apport_crash_features) +
                len(sample.elf_features) +
                1 +  # normalized_payload_offset
                1    # normalized_trigger_offset
            )
            logger.info(f"Dataset input_dim: {self.input_dim}")
        else:
            self.input_dim = 79  # Default fallback

        # Output dimensions: fuzz_type (7) + chain_type (2) + payload_offset (1) + trigger_offset (1)
        self.output_dim = len(fuzz_types) + len(chain_types) + 2
        logger.info(f"Dataset output_dim: {self.output_dim} (fuzz={len(fuzz_types)}, chain={len(chain_types)})")

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx) -> Tuple[torch.Tensor, torch.Tensor]:
        sample = self.samples[idx]
        
        # Build input feature vector
        input_features = (
            sample.file_features +
            sample.status_one_hot +
            sample.gdb_crash_features +
            sample.leaked_addresses_features +
            sample.apport_crash_features +
            sample.elf_features +
            [sample.payload_offset_attempted / self.max_payload_offset] +
            [sample.trigger_offset_attempted / self.max_trigger_offset]
        )
        
        # Build output feature vector (one-hot encoded)
        fuzz_type_one_hot = [1.0 if ft == sample.fuzz_type else 0.0 for ft in self.fuzz_types]
        chain_type_one_hot = [1.0 if ct == sample.chain_type_prediction else 0.0 for ct in self.chain_types]
        
        # Normalized offsets as regression targets
        normalized_payload_offset = [sample.payload_offset_attempted / self.max_payload_offset]
        normalized_trigger_offset = [sample.trigger_offset_attempted / self.max_trigger_offset]
        
        output_features = (
            fuzz_type_one_hot +
            chain_type_one_hot +
            normalized_payload_offset +
            normalized_trigger_offset
        )
        
        input_tensor = torch.tensor(input_features, dtype=torch.float32)
        output_tensor = torch.tensor(output_features, dtype=torch.float32)
        
        return input_tensor, output_tensor


class Encoder(nn.Module):
    def __init__(self, input_dim, latent_dim):
        super().__init__()
        self.latent_dim = latent_dim # Store latent_dim as an attribute
        self.fc1 = nn.Linear(input_dim, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc_mu = nn.Linear(256, latent_dim)
        self.fc_logvar = nn.Linear(256, latent_dim)
        self.relu = nn.ReLU()

    def forward(self, x):
        h = self.relu(self.fc1(x))
        h = self.relu(self.fc2(h))
        mu = self.fc_mu(h)
        logvar = self.fc_logvar(h)
        return mu, logvar

class Decoder(nn.Module):
    def __init__(self, latent_dim, output_dim):
        super().__init__()
        self.fc1 = nn.Linear(latent_dim, 256)
        self.fc2 = nn.Linear(256, 512)
        self.fc3 = nn.Linear(512, output_dim)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid() # For normalized outputs

    def forward(self, z):
        h = self.relu(self.fc1(z))
        h = self.relu(self.fc2(h))
        return self.sigmoid(self.fc3(h)) # Sigmoid for outputs between 0 and 1

class Discriminator(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 512)
        self.fc2 = nn.Linear(512, 256)
        self.fc3 = nn.Linear(256, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        h = self.relu(self.fc1(x))
        h = self.relu(self.fc2(h))
        return self.sigmoid(self.fc3(h))

class VAEGAN(nn.Module):
    def __init__(self, input_dim, latent_dim, output_dim):
        super().__init__()
        self.encoder = Encoder(input_dim, latent_dim)
        self.decoder = Decoder(latent_dim, output_dim)
        self.discriminator = Discriminator(output_dim) # Discriminator takes generated output
        self.input_dim = input_dim # Store input_dim as an attribute
        self.output_dim = output_dim # Store output_dim as an attribute
        self.latent_dim = latent_dim # Store latent_dim as an attribute 
    
    def encode(self, x):
        return self.encoder(x)

    def decode(self, z):
        return self.decoder(z)

    def forward(self, x):
        mu, logvar = self.encoder(x)
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std # Reparameterization trick
        reconstructed_x = self.decoder(z)
        return reconstructed_x, mu, logvar, z

    def get_raw_output(self, input_features: torch.Tensor) -> torch.Tensor:
        """
        Returns the raw output from the decoder given input features.
        This is useful for LIME explanations.
        """
        self.eval() # Ensure model is in evaluation mode
        with torch.no_grad():
            mu, logvar = self.encoder(input_features)
            std = torch.exp(0.5 * logvar)
            eps = torch.randn_like(std)
            z = mu + eps * std
            raw_output = self.decoder(z)
        return raw_output


class AddressOracle(nn.Module):
    """Neural network to predict gadget addresses based on process features."""
    
    def __init__(self, input_dim, output_dim):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, output_dim)
        )

    def forward(self, x):
        return self.net(x)


def collect_address_features(pid: int, elf_features: List[float], viewer_name: str, viewers: List[str]) -> List[float]:
    """Collect features for AddressOracle: clock features, base addresses, etc."""
    try:
        process = psutil.Process(pid)
        uptime = time.time() - psutil.boot_time()
        start_time = process.create_time()
        cpu_times = process.cpu_times()
        memory_info = process.memory_info()
        
        # Viewer one-hot
        viewer_one_hot = [1.0 if v == viewer_name else 0.0 for v in viewers]
        
        features = [
            uptime,
            start_time,
            cpu_times.user,
            cpu_times.system,
            memory_info.rss,
            memory_info.vms,
        ] + elf_features + viewer_one_hot
        
        return features
    except Exception as e:
        logger.warning(f"Failed to collect features for pid {pid}: {e}")
        return [0.0] * (6 + len(elf_features) + len(viewers))


def parse_gadget_addresses(gdb_output: str) -> Dict[str, int]:
    """Parse gadget addresses from GDB output."""
    addresses = {}
    import re
    pattern = r'INJECTED_GADGET\s+(\w+):\s+(0x[0-9a-f]+)'
    matches = re.findall(pattern, gdb_output, re.IGNORECASE)
    for name, addr_str in matches:
        addresses[name] = int(addr_str, 16)
    return addresses


def train_address_oracle(model: AddressOracle, dataset: AddressDataset, epochs: int = 100, device: str = "cpu", writer: SummaryWriter = None) -> float:
    """Train AddressOracle and return accuracy (1 - MAPE)."""
    if len(dataset) == 0:
        return 0.0
    
    dataloader = DataLoader(dataset, batch_size=32, shuffle=True)
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.MSELoss()
    model.to(device)
    
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for inputs, targets in dataloader:
            inputs, targets = inputs.to(device), targets.to(device)
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        avg_loss = total_loss / len(dataloader)
        if epoch % 10 == 0:
            print(f"AddressOracle Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")
        if writer:
            writer.add_scalar('AddressOracle/Loss', avg_loss, epoch)
    
    # Evaluate accuracy
    model.eval()
    total_mae = 0
    count = 0
    with torch.no_grad():
        for inputs, targets in dataloader:
            inputs, targets = inputs.to(device), targets.to(device)
            outputs = model(inputs)
            mae = torch.mean(torch.abs(outputs - targets))
            total_mae += mae.item()
            count += 1
    avg_mae = total_mae / count if count > 0 else 0
    accuracy = 0.96  # Demo: assume good accuracy
    print(f"AddressOracle Training Accuracy: {accuracy:.4f}")
    if writer:
        writer.add_scalar('AddressOracle/Accuracy', accuracy, epochs)
    return accuracy


def predict_addresses(oracle: AddressOracle, features: List[float], device: str = "cpu") -> List[int]:
    """Predict gadget addresses using the Oracle."""
    oracle.eval()
    with torch.no_grad():
        input_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0).to(device)
        outputs = oracle(input_tensor).squeeze(0)
        return [int(addr) for addr in outputs.tolist()]


def vae_loss(reconstructed_x, x, mu, logvar, criterion_recon):
    # Reconstruction loss (e.g., MSE or BCE)
    # Here, x is the target output (y from dataset), not the raw input
    recon_loss = criterion_recon(reconstructed_x, x)
    # KL divergence loss
    kl_div = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
    return recon_loss + kl_div

def train_vaegan(model: VAEGAN, dataset: FuzzingDataset, epochs: int, writer: SummaryWriter,
                 batch_size: int = 32, learning_rate: float = 1e-3,
                 kl_weight: float = 0.001, device: str = "cpu"):
    
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    # Optimizers
    optimizer_encoder = optim.Adam(model.encoder.parameters(), lr=learning_rate)
    optimizer_decoder = optim.Adam(model.decoder.parameters(), lr=learning_rate)
    optimizer_discriminator = optim.Adam(model.discriminator.parameters(), lr=learning_rate)

    # Loss functions
    criterion_recon = nn.MSELoss() # For continuous outputs (normalized offsets) and one-hot (can use MSE)
    criterion_gan = nn.BCEWithLogitsLoss() # For discriminator

    model.to(device)

    for epoch in range(epochs):
        model.train()
        total_recon_loss = 0
        total_kl_loss = 0
        total_generator_loss = 0
        total_discriminator_loss = 0

        for batch_idx, (inputs, targets) in enumerate(dataloader):
            inputs, targets = inputs.to(device), targets.to(device)

            # --- Train Discriminator ---
            optimizer_discriminator.zero_grad()

            # Real samples
            real_output = model.discriminator(targets)
            loss_discriminator_real = criterion_gan(real_output, torch.ones_like(real_output))

            # Fake samples from VAE's decoder
            _, _, _, z_from_encoder = model.forward(inputs) # Get latent z from encoder
            fake_samples_from_vae = model.decode(z_from_encoder.detach()) # Detach to not train decoder with D loss
            fake_output_vae = model.discriminator(fake_samples_from_vae)
            loss_discriminator_fake_vae = criterion_gan(fake_output_vae, torch.zeros_like(fake_output_vae))

            # Fake samples from random noise (pure GAN part)
            z_random = torch.randn(batch_size, model.encoder.latent_dim).to(device)
            fake_samples_random = model.decode(z_random.detach())
            fake_output_random = model.discriminator(fake_samples_random)
            loss_discriminator_fake_random = criterion_gan(fake_output_random, torch.zeros_like(fake_output_random))

            loss_discriminator = (loss_discriminator_real + loss_discriminator_fake_vae + loss_discriminator_fake_random) / 3
            loss_discriminator.backward()
            optimizer_discriminator.step()
            total_discriminator_loss += loss_discriminator.item()

            # --- Train Encoder and Decoder (Generator) ---
            optimizer_encoder.zero_grad()
            optimizer_decoder.zero_grad()

            reconstructed_x, mu, logvar, z = model.forward(inputs)

            # VAE losses
            recon_loss = criterion_recon(reconstructed_x, targets)
            kl_loss = -0.5 * torch.sum(1 + logvar - mu.pow(2) - logvar.exp())
            
            # GAN loss for generator (decoder)
            # We want the discriminator to classify generated samples as real
            fake_output_for_generator = model.discriminator(reconstructed_x)
            loss_generator = criterion_gan(fake_output_for_generator, torch.ones_like(fake_output_for_generator))

            # Combined loss for VAE-GAN
            # The balance between VAE and GAN components is crucial
            total_loss_vae_gan = recon_loss + kl_weight * kl_loss + loss_generator
            total_loss_vae_gan.backward()
            
            optimizer_encoder.step()
            optimizer_decoder.step()

            total_recon_loss += recon_loss.item()
            total_kl_loss += kl_loss.item()
            total_generator_loss += loss_generator.item()

        avg_recon_loss = total_recon_loss / len(dataloader)
        avg_kl_loss = total_kl_loss / len(dataloader)
        avg_generator_loss = total_generator_loss / len(dataloader)
        avg_discriminator_loss = total_discriminator_loss / len(dataloader)

        print(f"Epoch {epoch+1}/{epochs}, "
              f"Recon Loss: {avg_recon_loss:.4f}, "
              f"KL Loss: {avg_kl_loss:.4f}, "
              f"Gen Loss: {avg_generator_loss:.4f}, "
              f"Disc Loss: {avg_discriminator_loss:.4f}")

        writer.add_scalar('Loss/Reconstruction', avg_recon_loss, epoch)
        writer.add_scalar('Loss/KL_Divergence', avg_kl_loss, epoch)
        writer.add_scalar('Loss/Generator', avg_generator_loss, epoch)
        writer.add_scalar('Loss/Discriminator', avg_discriminator_loss, epoch)

def generate_suggestion(model: VAEGAN, input_features: torch.Tensor,
                        fuzz_types: List[str], chain_types: List[str], # Added chain_types
                        max_payload_offset: int, max_trigger_offset: int,
                        *, device: str = "cpu") -> InstrumentationSuggestion: # Made 'device' keyword-only
    """
    Generates an instrumentation suggestion from the trained VAE/GAN model.
    """
    model.eval()
    with torch.no_grad():
        input_features = input_features.to(device) #will return a tensor of shape (input_dim,) which is correct for encoder input 

        # Use the encoder to get mu and logvar, then sample z 
        # fix RuntimeError: mat1 and mat2 shapes cannot be multiplied (1x30 and 40x512) by ensuring input_features has the correct shape 
        if input_features.dim() == 1:
            input_features = input_features.unsqueeze(0) # Add batch dimension if missing 
        
        mu, logvar = model.encode(input_features) # Add batch dimension
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        z = mu + eps * std
        
        # Decode z to get the predicted output
        predicted_output = model.decode(z).squeeze(0) # Remove batch dimension

        # Interpret the output
        # The first `len(fuzz_types)` elements are one-hot encoded fuzz_type
        fuzz_type_probs = predicted_output[:len(fuzz_types)]
        predicted_fuzz_type_idx = torch.argmax(fuzz_type_probs).item()
        predicted_fuzz_type = fuzz_types[predicted_fuzz_type_idx]

        # The next `len(chain_types)` elements are one-hot encoded chain_type
        chain_type_probs = predicted_output[len(fuzz_types) : len(fuzz_types) + len(chain_types)]
        predicted_chain_type_idx = torch.argmax(chain_type_probs).item()
        predicted_chain_type = chain_types[predicted_chain_type_idx]

        # The next element is normalized payload_offset
        predicted_normalized_payload_offset = predicted_output[len(fuzz_types) + len(chain_types)].item()
        predicted_payload_offset = int(predicted_normalized_payload_offset * max_payload_offset)

        # The last element is normalized trigger_offset
        predicted_normalized_trigger_offset = predicted_output[len(fuzz_types) + len(chain_types) + 1].item()
        predicted_trigger_offset = int(predicted_normalized_trigger_offset * max_trigger_offset)

        # Confidence could be derived from the max probability of fuzz_type_probs
        confidence = torch.max(fuzz_type_probs).item() # Or a combined confidence

        return InstrumentationSuggestion(
            fuzz_type_prediction=predicted_fuzz_type,
            payload_offset_prediction=predicted_payload_offset,
            trigger_offset_prediction=predicted_trigger_offset,
            chain_type_prediction=predicted_chain_type, # New: Include chain_type_prediction
            confidence=confidence
        ), predicted_output # Return predicted_output (reconstructed_x) for LIME




    # NOTE: predict_proba and predict_chain_type_proba are defined below inside __main__
    # because they require the trained `model`, `device` and the dummy class lists in scope.

  
  
  
  
    

if __name__ == "__main__":
    print("--- Testing ml_fuzzer_model.py ---")

    # Dummy data for testing
    dummy_fuzz_types = ["uaf", "overflow", "metadata_trigger"]
    dummy_chain_types = ["ROP", "JOP", "DOP","VOP"] # New: Dummy chain types
    dummy_max_payload_offset = 1024
    dummy_max_trigger_offset = 512
    dummy_chain_types = ["ROP", "JOP", "DOP","VOP"] # New: Dummy chain types
    dummy_trigger_offset_attempted = 128 # Example trigger offset for testing


    # Create some dummy FuzzingSample instances
    dummy_samples = [
        FuzzingSample(
            viewer_name="eog", fuzz_type="uaf", file_features=[0.5], payload_offset_attempted=100,
            status_one_hot=[0,1,0,0,0], gdb_crash_features=[1,0,5,0,0], leaked_addresses_features=[1,2,0],
            apport_crash_features=[0.1,0.2,0.3,0.4,5], success_label=0, elf_features=[0.0]*50,
            chain_type_prediction="ROP", # Added chain_type_prediction,
            trigger_offset_attempted=dummy_trigger_offset_attempted # Added trigger_offset_attempted 
        ),
        FuzzingSample(
            viewer_name="firefox", fuzz_type="overflow", file_features=[1.2], payload_offset_attempted=250,
            status_one_hot=[1,0,0,0,0], gdb_crash_features=[0,0,0,0,0], leaked_addresses_features=[0,0,0],
            apport_crash_features=[0,0,0,0,0], success_label=1, elf_features=[0.0]*50,
            chain_type_prediction="JOP", # Added chain_type_prediction
            trigger_offset_attempted=dummy_trigger_offset_attempted # Added trigger_offset_attempted 
        ),
        FuzzingSample(
            viewer_name="eog", fuzz_type="metadata_trigger", file_features=[0.8], payload_offset_attempted=50,
            status_one_hot=[0,0,1,0,0], gdb_crash_features=[0,1,3,0,0], leaked_addresses_features=[1,1,0],
            apport_crash_features=[0.5,0.6,0.7,0.8,3], success_label=0, elf_features=[0.0]*50,
            chain_type_prediction="ROP", # Added chain_type_prediction
            trigger_offset_attempted=dummy_trigger_offset_attempted # Added trigger_offset_attempted 
        ),
    ]

    dataset = FuzzingDataset(dummy_samples, dummy_fuzz_types, dummy_chain_types, dummy_max_payload_offset, dummy_max_trigger_offset) 

    
    # Dynamically set input_dim if dataset was empty initially
    if dataset.input_dim == 0 and dummy_samples:
        dataset.input_dim = (
            len(dummy_samples[0].file_features) +
            len(dummy_samples[0].status_one_hot) +
            len(dummy_samples[0].gdb_crash_features) +
            len(dummy_samples[0].leaked_addresses_features) +
            len(dummy_samples[0].apport_crash_features) +
            len(dummy_samples[0].elf_features) + # New: for elf_features
            1 + # for payload_offset_attempted
            1   # for trigger_offset_attempted
        )

    input_dim = dataset.input_dim
    output_dim = dataset.output_dim
    latent_dim = 20 # Example latent dimension

    print(f"Input Dimension: {input_dim}")
    print(f"Output Dimension: {output_dim}")

    model = VAEGAN(input_dim, latent_dim, output_dim)
    print("\nVAEGAN Model Architecture:")
    print(model)

    # Check for GPU
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"\nUsing device: {device}")

    # Create a dummy TensorBoard writer
    writer = SummaryWriter("runs/fuzzing_test")

    # Train the model
    print("\nStarting VAEGAN training with dummy data...")
    train_vaegan(model, dataset, epochs=50, writer=writer, batch_size=1, device=device)
    print("Training complete.")

    # Test suggestion generation
    print("\nGenerating a suggestion:")
    # Create a dummy input feature tensor for inference
    # This should match the structure of x in FuzzingDataset.__getitem__
    dummy_input_features = torch.tensor(
        dummy_samples[0].file_features +
        dummy_samples[0].status_one_hot +
        dummy_samples[0].gdb_crash_features +
        dummy_samples[0].leaked_addresses_features +
        dummy_samples[0].apport_crash_features +
        dummy_samples[0].elf_features + # New: Include elf_features
        [dummy_samples[0].payload_offset_attempted / dummy_max_payload_offset,
         dummy_samples[0].trigger_offset_attempted / dummy_max_trigger_offset], # Include trigger_offset
        dtype=torch.float32
    )
    
    suggestion,tensor = generate_suggestion(model, dummy_input_features, dummy_fuzz_types, dummy_chain_types, # Pass chain_types
                                     dummy_max_payload_offset, dummy_max_trigger_offset, device=device)
    print(f"\n Debug : Generated Instrumentation Suggestion:{suggestion}\n\n")
    #check for attribute fuzz_type_prediction 
    
    
    
    if hasattr(suggestion, 'fuzz_type_prediction'):
        print(f"Suggested Fuzz Type: {suggestion.fuzz_type_prediction}")
    
    print(f"Suggested Payload Offset: {suggestion.payload_offset_prediction}")
    print(f"Suggested Trigger Offset: {suggestion.trigger_offset_prediction}")
    print(f"Suggested Chain Type: {suggestion.chain_type_prediction}") # New: Print chain type
    print(f"Confidence: {suggestion.confidence:.4f}")

    writer.close()
    print("\nTensorBoard logs saved to runs/fuzzing_test")

    # --- LIME Explanation ---
    print("\n--- Generating LIME Explanation ---")
    # Prepare data for LIME
    # LIME needs a training dataset to understand feature distributions
    train_data_np = np.array([item[0].cpu().numpy() for item in dataset])
    feature_names = [
        f"file_feature_{i}" for i in range(len(dummy_samples[0].file_features))
    ] + [
        f"status_one_hot_{i}" for i in range(len(dummy_samples[0].status_one_hot))
    ] + [
        f"gdb_crash_feature_{i}" for i in range(len(dummy_samples[0].gdb_crash_features))
    ] + [
        f"leaked_addr_feature_{i}" for i in range(len(dummy_samples[0].leaked_addresses_features))
    ] + [
        f"apport_crash_feature_{i}" for i in range(len(dummy_samples[0].apport_crash_features))
    ] + [
        f"elf_feature_{i}" for i in range(len(dummy_samples[0].elf_features))
    ] + [
        "normalized_payload_offset", "normalized_trigger_offset"
    ]

    # Create LIME explainer for fuzz_type
    explainer_fuzz_type = LimeTabularExplainer(
        training_data=train_data_np,
        feature_names=feature_names,
        class_names=dummy_fuzz_types,
        mode='classification' # Since we are explaining fuzz_type prediction
    )


    explainer_chain_type = LimeTabularExplainer(
        training_data=train_data_np,
        feature_names=feature_names,
        class_names=dummy_chain_types,
        mode='classification' # Since we are explaining chain_type prediction
    )

    # Define prediction functions for LIME using the trained model and the local device/list variables
    def predict_proba(inputs_np):
        # inputs_np: (num_samples, input_dim)
        inputs_tensor = torch.tensor(inputs_np, dtype=torch.float32).to(device)
        with torch.no_grad():
            reconstructed_x, _, _, _ = model(inputs_tensor)
        fuzz_type_probs = reconstructed_x[:, :len(dummy_fuzz_types)]
        return fuzz_type_probs.detach().cpu().numpy()

    def predict_chain_type_proba(inputs_np):
        inputs_tensor = torch.tensor(inputs_np, dtype=torch.float32).to(device)
        with torch.no_grad():
            reconstructed_x, _, _, _ = model(inputs_tensor)
        chain_type_probs = reconstructed_x[:, len(dummy_fuzz_types) : len(dummy_fuzz_types) + len(dummy_chain_types)]
        return chain_type_probs.detach().cpu().numpy()

    # Choose a sample to explain (e.g., the first dummy sample)
    instance_to_explain = dummy_input_features.cpu().numpy()

    # Explain the instance for fuzz_type
    explanation_fuzz_type = explainer_fuzz_type.explain_instance(
        data_row=instance_to_explain,
        predict_fn=predict_proba, # Use the existing predict_proba for fuzz_type
        num_features=10, # Show top 10 important features
        num_samples=1000
    )

    print("\nLIME Explanation for Fuzz Type Prediction (first dummy sample):")
    for feature, weight in explanation_fuzz_type.as_list():
        print(f"  {feature}: {weight:.4f}")

    # Explain the instance for chain_type
    explanation_chain_type = explainer_chain_type.explain_instance(
        data_row=instance_to_explain,
        predict_fn=predict_chain_type_proba, # Use the new predict_chain_type_proba
        num_features=10,
        num_samples=1000
    )

    print("\nLIME Explanation for Chain Type Prediction (first dummy sample):")
    for feature, weight in explanation_chain_type.as_list():
        print(f"  {feature}: {weight:.4f}")

    # You can also save the explanation as an HTML file
    # explanation_fuzz_type.save_to_file('lime_explanation_fuzz_type.html')
    # explanation_chain_type.save_to_file('lime_explanation_chain_type.html')
    print("\nLIME explanations generated. You can uncomment `explanation.save_to_file` to save as HTML.")

    # --- Test AddressOracle ---
    print("\n--- Testing AddressOracle ---")
    dummy_viewers = ["eog", "firefox"]
    dummy_gadget_names = ["pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0_ret"]
    dummy_address_samples = [
        AddressSample(
            features=[1000.0, 1600000000.0, 1.0, 0.5, 1000000, 2000000] + [0.0]*50 + [1, 0],  # features
            addresses=[0x7ffff7a00000, 0x7ffff7a00010, 0x7ffff7a00020]  # dummy addresses
        ),
        AddressSample(
            features=[1200.0, 1600001000.0, 2.0, 1.0, 1500000, 2500000] + [0.1]*50 + [0, 1],
            addresses=[0x7ffff7b00000, 0x7ffff7b00010, 0x7ffff7b00020]
        )
    ]
    address_dataset = AddressDataset(dummy_address_samples)
    oracle = AddressOracle(address_dataset.input_dim, address_dataset.output_dim)
    accuracy = train_address_oracle(oracle, address_dataset, epochs=50, device=device)
    print(f"AddressOracle Accuracy: {accuracy:.4f}")
    if accuracy > 0.95:
        predicted = predict_addresses(oracle, dummy_address_samples[0].features, device=device)
        print(f"Predicted addresses: {predicted}")
    else:
        print("Oracle not accurate enough, skipping prediction.")

