import os
import torch
import numpy as np
from typing import List, Dict, Optional, Union, Tuple
from lime.lime_tabular import LimeTabularExplainer
from torch.utils.tensorboard import SummaryWriter
from torchvision import transforms
import matplotlib.pyplot as plt
import io
import base64
from PIL import Image
# Assuming VAEGAN and FuzzingDataset are available from ml_fuzzer_model and data_processor
# To avoid circular imports, we'll pass the model and dataset directly.
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LimeExplainer:
    def __init__(self, model, feature_names: List[str], class_names: Optional[List[str]] = None,
                 data_sample: np.ndarray = None, mode: str = "classification",
                 max_payload_offset: int = 4096, device: str = "cpu"):
        self.model = model
        self.feature_names = feature_names
        self.class_names = class_names
        self.data_sample = data_sample
        self.mode = mode
        self.max_payload_offset = max_payload_offset
        self.device = device
        
        if data_sample is not None:
            self.explainer = LimeTabularExplainer(
                data_sample, 
                feature_names=feature_names,
                class_names=class_names,
                mode=mode,
                verbose=False
            )
        else:
            self.explainer = None

    def _model_predict_proba_fuzz_type(self, input_data: np.ndarray) -> np.ndarray:
        """Prediction function for LIME for fuzz_type (classification)."""
        with torch.no_grad():
            input_tensor = torch.tensor(input_data, dtype=torch.float32).to(self.device)
            if input_tensor.dim() == 1:
                input_tensor = input_tensor.unsqueeze(0)
            
            # Model forward returns: reconstructed_x, mu, logvar, z
            reconstructed_x, mu, logvar, z = self.model(input_tensor)
            
            # Extract fuzz_type predictions (first N elements based on number of fuzz types)
            # Assuming the model outputs: [fuzz_type_logits, chain_type_logits, payload_offset, trigger_offset]
            num_fuzz_types = len(self.class_names) if self.class_names else 7  # Default fallback
            fuzz_type_logits = reconstructed_x[:, :num_fuzz_types]
            probabilities = torch.softmax(fuzz_type_logits, dim=1).cpu().numpy()
            
            return probabilities

    def _model_predict_payload_offset(self, input_data: np.ndarray) -> np.ndarray:
        """Prediction function for LIME for payload_offset (regression)."""
        with torch.no_grad():
            input_tensor = torch.tensor(input_data, dtype=torch.float32).to(self.device)
            if input_tensor.dim() == 1:
                input_tensor = input_tensor.unsqueeze(0)
            
            # Model forward returns: reconstructed_x, mu, logvar, z
            reconstructed_x, mu, logvar, z = self.model(input_tensor)
            
            # Extract payload_offset prediction
            # Assuming structure: [fuzz_type_logits, chain_type_logits, payload_offset, trigger_offset]
            num_fuzz_types = 7  # Default, should match model
            num_chain_types = 2  # Default, should match model
            
            # payload_offset is at position num_fuzz_types + num_chain_types
            payload_offset_idx = num_fuzz_types + num_chain_types
            payload_offset_normalized = reconstructed_x[:, payload_offset_idx:payload_offset_idx+1]
            
            # Denormalize: multiply by max_payload_offset
            payload_offset = (payload_offset_normalized * self.max_payload_offset).cpu().numpy()
            
            return payload_offset

    def explain_fuzz_type_prediction(self, instance: np.ndarray) -> Optional[List[Tuple[str, float]]]:
        """Explains the fuzz_type prediction for a given instance."""
        if self.explainer is None:
            return None
        
        try:
            explanation = self.explainer.explain_instance(
                instance, 
                self._model_predict_proba_fuzz_type,
                num_features=len(self.feature_names),
                top_labels=len(self.class_names) if self.class_names else 7
            )
            # explanation.as_list() already returns [(feature_name, weight), ...]
            # No need to map indices to feature names
            return explanation.as_list()
        except Exception as e:
            logger.error(f"Error explaining fuzz_type prediction: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

    def explain_payload_offset_prediction(self, instance: np.ndarray) -> Optional[List[Tuple[str, float]]]:
        """Explains the payload_offset prediction for a given instance."""
        if self.explainer is None:
            return None
        
        try:
            explanation = self.explainer.explain_instance(
                instance,
                self._model_predict_payload_offset,
                num_features=len(self.feature_names)
            )
            # explanation.as_list() already returns [(feature_name, weight), ...]
            # No need to map indices to feature names
            return explanation.as_list()
        except Exception as e:
            logger.error(f"Error explaining payload_offset prediction: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

def plot_and_log_lime_explanation(writer: SummaryWriter, explanation_list: List[tuple[str, float]],
                                  title: str, global_step: int, tag: str):
    """
    Plots a LIME explanation as a bar chart and logs it to TensorBoard.
    """
    if not explanation_list:
        print(f"Warning: No explanation data to plot for tag: {tag}")
        return

    features = [item[0] for item in explanation_list]
    weights = [item[1] for item in explanation_list]

    # Sort by weight for better visualization
    sorted_explanation = sorted(zip(features, weights), key=lambda x: x[1], reverse=True)
    sorted_features = [item[0] for item in sorted_explanation]
    sorted_weights = [item[1] for item in sorted_explanation]

    fig, ax = plt.subplots(figsize=(10, 6))
    y_pos = np.arange(len(sorted_features))
    
    ax.barh(y_pos, sorted_weights, align='center', color=['green' if w > 0 else 'red' for w in sorted_weights])
    ax.set_yticks(y_pos)
    ax.set_yticklabels(sorted_features)
    ax.invert_yaxis()  # features with high weight at the top
    ax.set_xlabel('Weight')
    ax.set_title(title)
    plt.tight_layout()

    # Save plot to a BytesIO object and then to TensorBoard
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image = Image.open(buf)
    image = transforms.ToTensor()(image)
    writer.add_image(tag, image, global_step=global_step)
    
    # Also save as a local PNG for debugging/inspection
    output_dir = "runs/lime_explanations_plots"
    os.makedirs(output_dir, exist_ok=True)
    safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '.', '_')).rstrip()
    plt.savefig(os.path.join(output_dir, f"{safe_title.replace(' ', '_')}_{global_step}.png"))

    plt.close(fig)
    buf.close()
    print(f"Logged LIME explanation plot to TensorBoard and saved locally for tag: {tag}")

if __name__ == "__main__":
    print("--- Testing lime_explainer.py (dummy setup) ---")

    # Dummy Model (VAEGAN)
    class DummyVAEGAN(torch.nn.Module):
        def __init__(self, input_dim, output_dim):
            super().__init__()
            self.encoder = torch.nn.Linear(input_dim, 10)
            self.decoder = torch.nn.Linear(10, output_dim)
            self.output_dim = output_dim
            self.fuzz_type_output_dim = 7 # Assuming 7 fuzz types
            self.chain_type_output_dim = 2 # Assuming 2 chain types (ROP, JOP)

        def forward(self, x):
            latent = self.encoder(x)
            reconstructed_x = self.decoder(latent)
            return None, None, reconstructed_x # Return dummy mu, logvar, reconstructed_x

    input_dim = 50 + 5 + 5 + 3 + 5 + 1 + 1 # Example feature vector size
    output_dim = 7 + 2 + 2 # fuzz_type (7), chain_type (2), payload_offset (1), trigger_offset (1)
    dummy_model = DummyVAEGAN(input_dim, output_dim)
    device = "cpu"

    # Dummy Data Sample (representative of training data)
    dummy_data_sample = np.random.rand(100, input_dim).astype(np.float32)
    
    # Dummy Feature Names
    dummy_feature_names = [f"feature_{i}" for i in range(input_dim)]
    dummy_class_names = [f"fuzz_type_{i}" for i in range(7)]
    dummy_max_payload_offset = 4096

    # Test Classification Explainer (fuzz_type)
    print("\nTesting Fuzz Type Explanation:")
    lime_explainer_fuzz_type = LimeExplainer(
        model=dummy_model,
        feature_names=dummy_feature_names,
        class_names=dummy_class_names,
        data_sample=dummy_data_sample,
        mode="classification",
        device=device
    )
    sample_instance_fuzz_type = np.random.rand(input_dim).astype(np.float32)
    fuzz_type_explanation = lime_explainer_fuzz_type.explain_fuzz_type_prediction(sample_instance_fuzz_type)
    if fuzz_type_explanation:
        print("Fuzz Type Explanation (top 5 features):", fuzz_type_explanation[:5])
        # Log to dummy writer
        dummy_writer = SummaryWriter("runs/dummy_lime_fuzz_type")
        plot_and_log_lime_explanation(dummy_writer, fuzz_type_explanation, "Dummy Fuzz Type Explanation", 1, "LIME/DummyFuzzType")
        dummy_writer.close()
        print("Fuzz Type Explanation PASSED")
    else:
        print("Fuzz Type Explanation FAILED")

    # Test Regression Explainer (payload_offset)
    print("\nTesting Payload Offset Explanation:")
    lime_explainer_payload_offset = LimeExplainer(
        model=dummy_model,
        feature_names=dummy_feature_names,
        class_names=None, # Not applicable for regression
        data_sample=dummy_data_sample,
        mode="regression",
        max_payload_offset=dummy_max_payload_offset,
        device=device
    )
    sample_instance_payload_offset = np.random.rand(input_dim).astype(np.float32)
    payload_offset_explanation = lime_explainer_payload_offset.explain_payload_offset_prediction(sample_instance_payload_offset)
    if payload_offset_explanation:
        print("Payload Offset Explanation (top 5 features):", payload_offset_explanation[:5])
        # Log to dummy writer
        dummy_writer = SummaryWriter("runs/dummy_lime_payload_offset")
        plot_and_log_lime_explanation(dummy_writer, payload_offset_explanation, "Dummy Payload Offset Explanation", 1, "LIME/DummyPayloadOffset")
        dummy_writer.close()
        print("Payload Offset Explanation PASSED")
    else:
        print("Payload Offset Explanation FAILED")

    print("\nDummy LIME explanation generation complete. Check 'runs/dummy_lime_fuzz_type' and 'runs/dummy_lime_payload_offset' for TensorBoard logs and 'runs/lime_explanations_plots' for local PNGs.")
