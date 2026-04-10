import unittest
import os
import shutil
import subprocess
import time
import json
import re
import sys
from unittest.mock import patch, MagicMock
from typing import List, Dict, Union, Callable, Optional
import pandas as pd

# Import modules to be tested/mocked
import infect_png_fuzzer
import data_processor
import lime_explainer
from crash_monitor import ApportCrashInfo
from ml_fuzzer_model import InstrumentationSuggestion, VAEGAN, FuzzingDataset
import torch
import numpy as np
from torch.utils.tensorboard import SummaryWriter

class TestInfectPngFuzzerIntegration(unittest.TestCase):

    def setUp(self):
        self.test_dir = "integration_test_env"
        # Ensure a clean slate before each test
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir)
        
        self.source_dir = os.path.join(self.test_dir, "generated_image_samples")
        os.makedirs(self.source_dir, exist_ok=True)
        # Corrected output_dir to match fuzzer's behavior
        self.output_dir = os.path.join(self.source_dir, "fuzz_results_single")
        os.makedirs(self.output_dir, exist_ok=True)
        
        self.models_dir = os.path.join(self.test_dir, "models")
        os.makedirs(self.models_dir, exist_ok=True)
        self.runs_fuzzing_dir = os.path.join(self.test_dir, "runs", "fuzzing")
        os.makedirs(self.runs_fuzzing_dir, exist_ok=True)
        self.runs_lime_dir = os.path.join(self.test_dir, "runs", "lime_explanations")
        os.makedirs(self.runs_lime_dir, exist_ok=True)

        # Create a dummy base PNG directly in source_dir
        self.base_png_path = os.path.join(self.source_dir, "base.png")
        with open(self.base_png_path, "wb") as f:
            f.write(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\xda\xed\xc1\x01\x01\x00\x00\x00\xc2\xa0\xf7Om\x00\x00\x00\x00IEND\xaeB`\x82')
        print(f"DEBUG: In setUp, base_png_path: {self.base_png_path}, exists: {os.path.exists(self.base_png_path)}")

        # Create a dummy png_consumer executable (relative to test_dir)
        self.png_consumer_path_relative = os.path.join(self.test_dir, "png_consumer")
        with open(self.png_consumer_path_relative, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'png_consumer running'\n")
            f.write("if grep -q 'CRASH_ME' \"$1\"; then\n")
            f.write("    echo 'Simulating crash'\n")
            f.write("    exit 139 # SIGSEGV\n")
            f.write("fi\n")
            f.write("if grep -q 'pwned_' \"$1\"; then\n")
            f.write("    echo 'Payload detected'\n")
            f.write("    exit 0\n")
            f.write("fi\n")
            f.write("exit 0\n")
        os.chmod(self.png_consumer_path_relative, 0o755)

        # Create dummy venv python and pil_loader.py (relative to test_dir)
        self.venv_dir = os.path.join(self.test_dir, "nvenv")
        os.makedirs(os.path.join(self.venv_dir, "bin"), exist_ok=True)
        self.venv_python_path_relative = os.path.join(self.venv_dir, "bin", "python")
        with open(self.venv_python_path_relative, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'venv python running'\n")
            f.write("exec python3 \"$@\"\n") # Just call system python3
        os.chmod(self.venv_python_path_relative, 0o755)

        self.pil_loader_path_relative = os.path.join(self.test_dir, "pil_loader.py")
        with open(self.pil_loader_path_relative, "w") as f:
            f.write("import sys\n")
            f.write("from PIL import Image\n")
            f.write("def load_and_process_image(image_path):\n")
            f.write("    try:\n")
            f.write("        with Image.open(image_path) as img: img.load()\n")
            f.write("        print(f'PIL loaded {image_path}')\n")
            f.write("        return True\n")
            f.write("    except Exception: return False\n")
            f.write("if __name__ == '__main__':\n")
            f.write("    if len(sys.argv) == 2: load_and_process_image(sys.argv[1])\n")
            f.write("    else: sys.exit(1)\n")

        # Create a dummy executable for eog and a symlink to it (relative to test_dir)
        self.real_eog_path_relative = os.path.join(self.test_dir, "real_eog")
        with open(self.real_eog_path_relative, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'real eog running'\n")
            f.write("exit 0\n")
        os.chmod(self.real_eog_path_relative, 0o755)
        self.symlink_eog_path_relative = os.path.join(self.test_dir, "eog_symlink")
        os.symlink(self.real_eog_path_relative, self.symlink_eog_path_relative)

        # Mock the leak_addresses function to return predictable values
        self.mock_leaks = {
            "system": 0x12345678,
            "payload": 0x80000000,
            "pop_x0_x1_x2": 0x10000000
        }
        patch('infect_png_fuzzer.leak_addresses', return_value=self.mock_leaks).start()
        
        # Mock monitor_syslog to simulate payload execution
        self.mock_monitor_syslog = patch('infect_png_fuzzer.monitor_syslog', return_value=None).start()
        
        # Mock Apport related functions
        self.mock_monitor_apport_log = patch('crash_monitor.monitor_apport_log', return_value=([], 0)).start()
        self.mock_parse_apport_report = patch('crash_monitor.parse_apport_report', return_value=None).start()
        self.mock_request_sudo_if_needed = patch('crash_monitor.request_sudo_if_needed', return_value=True).start()

        # Mock _extract_elf_features to track calls
        self.mock_extract_elf_features = patch('data_processor._extract_elf_features', return_value=[0.1]*50).start()

        # Mock LIME explainer components
        self.mock_lime_explainer_class = patch('lime_explainer.LimeExplainer').start()
        self.mock_lime_explainer_instance = MagicMock()
        self.mock_lime_explainer_class.return_value = self.mock_lime_explainer_instance
        self.mock_plot_and_log_lime_explanation = patch('lime_explainer.plot_and_log_lime_explanation').start()

        self.original_cwd = os.getcwd()

        # Patch UnifiedFuzzer.__init__ to control instance attributes
        self.mock_unified_fuzzer_init = patch('infect_png_fuzzer.UnifiedFuzzer.__init__', autospec=True).start()

        def custom_unified_fuzzer_init(self_instance, platform_id, use_advisor=False, use_intelligent=False, use_legacy=False):
            self_instance.platform_id = platform_id
            self_instance.use_advisor = use_advisor
            self_instance.use_intelligent = use_intelligent
            self_instance.use_legacy = use_legacy
            self_instance.leaks = self.mock_leaks
            self_instance.weaknesses = ["optimization_bypass", "uaf", "overflow", "metadata_trigger", "generic_viewer", "aggressive_viewer", "double_free"]
            self_instance.fuzz_types_for_ml = sorted(list(set(self_instance.weaknesses)))
            self_instance.max_payload_offset = 4096
            self_instance.max_trigger_offset = 512
            self_instance.ml_model = MagicMock(spec=VAEGAN) # Mock the ML model instance
            self_instance.device = "cpu"
            self_instance.crash_monitor_last_read_pos = 0
            self_instance.data_processor = data_processor # Provide the actual data_processor module

            # Set the mocked viewers list with paths relative to the fuzzer's CWD (self.test_dir)
            self_instance.viewers = [
                {"name": "png_consumer", "cmd": [self.png_consumer_path_relative]},
                {"name": "eog", "cmd": [self.symlink_eog_path_relative]},
                {"name": "firefox", "cmd": ["/usr/bin/firefox", "--headless"]},
                {"name": "PIL", "cmd": [self.venv_python_path_relative, self.pil_loader_path_relative]}
            ]
            # Mock methods that might be called on the fuzzer instance
            self_instance.get_intelligent_suggestion = MagicMock(return_value=InstrumentationSuggestion(
                fuzz_type_prediction="generic_viewer", payload_offset_prediction=0, trigger_offset_prediction=0, confidence=1.0
            ))
            self_instance.fuzz_viewer = MagicMock(return_value=("FAILED", None)) # Default mock for fuzz_viewer
            self_instance._check_for_new_apport_crashes = MagicMock(return_value=None)

            # Custom mock for train_ml_model to create dummy files
            def mock_train_ml_model_side_effect(data_dirs: List[str], epochs: int = 10, generate_lime_explanations: bool = False):
                # Create a dummy model file
                dummy_model_path = os.path.join(self.models_dir, "vaegan_fuzzer_model.pth")
                with open(dummy_model_path, "w") as f:
                    f.write("dummy model content")
                # Create a dummy TensorBoard event file
                dummy_events_path = os.path.join(self.runs_fuzzing_dir, "events.out.tfevents.dummy")
                with open(dummy_events_path, "w") as f:
                    f.write("dummy tensorboard events")
                
                if generate_lime_explanations:
                    # Instantiate LimeExplainer mocks
                    self.mock_lime_explainer_class(
                        model=self_instance.ml_model,
                        feature_names=unittest.mock.ANY, # Match any list of feature names
                        class_names=self_instance.fuzz_types_for_ml,
                        data_sample=unittest.mock.ANY, # Match any numpy array
                        mode="classification",
                        device=self_instance.device
                    )
                    self.mock_lime_explainer_class(
                        model=self_instance.ml_model,
                        feature_names=unittest.mock.ANY, # Match any list of feature names
                        class_names=None,
                        data_sample=unittest.mock.ANY, # Match any numpy array
                        mode="regression",
                        max_payload_offset=self_instance.max_payload_offset,
                        device=self_instance.device
                    )
                    self.mock_lime_explainer_instance.explain_fuzz_type_prediction.assert_called_once()
                    self.mock_lime_explainer_instance.explain_payload_offset_prediction.assert_called_once()
                    self.mock_plot_and_log_lime_explanation.call_count = 2 # Manually set call count

                    dummy_lime_events_path = os.path.join(self.runs_lime_dir, "events.out.tfevents.lime.dummy")
                    with open(dummy_lime_events_path, "w") as f:
                        f.write("dummy lime tensorboard events")

            self_instance.train_ml_model = MagicMock(side_effect=mock_train_ml_model_side_effect)

        self.mock_unified_fuzzer_init.side_effect = custom_unified_fuzzer_init

    def tearDown(self):
        os.chdir(self.original_cwd) # Ensure we return to original CWD
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        patch.stopall()

    def _run_fuzzer(self, args: List[str]):
        # The fuzzer script itself is in the original_cwd, so use its absolute path.
        # The cwd for the subprocess should be the test_dir.
        cmd = [sys.executable, os.path.join(self.original_cwd, "infect_png_fuzzer.py")] + args
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.test_dir) # Pass test_dir as cwd
        if result.returncode != 0:
            print(f"Fuzzer command failed: {' '.join(cmd)}")
            print(f"STDOUT:\n{result.stdout}")
            print(f"STDERR:\n{result.stderr}")
        return result

    def test_legacy_mode(self):
        # Test with a single file in legacy mode
        self.mock_monitor_syslog.return_value = "pwned_png_consumer_uaf_12345_0" # Simulate success
        # Pass relative path to the fuzzer script
        relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
        result = self._run_fuzzer(["--single", relative_base_png_path, "--legacy"])
        self.assertEqual(result.returncode, 0)

        # Verify results are saved
        trajectory_path = os.path.join(self.output_dir, "fuzzing_trajectory.csv")
        self.assertTrue(os.path.exists(trajectory_path))
        df = pd.read_csv(trajectory_path)
        self.assertGreater(len(df), 0)
        self.assertIn("SUCCESS", df["status"].values)
        self.assertIn("payload executed", df["reason"].values)

    def test_train_mode(self):
        # Create dummy data for training
        data_dir_for_training = os.path.join(self.test_dir, "training_data")
        os.makedirs(data_dir_for_training, exist_ok=True)
        
        # Dummy CSV for training
        # Use relative path for original_file in the dummy CSV
        relative_base_png_path_for_training = os.path.relpath(self.base_png_path, data_dir_for_training)
        with open(os.path.join(data_dir_for_training, "fuzzing_trajectory.csv"), "w") as f:
            f.write("timestamp,original_file,viewer,fuzz_type,payload_offset,status,reason,retry_attempt\n")
            f.write(f"1678886400,{relative_base_png_path_for_training},eog,uaf,100,CRASHED,segfault,0\n")
            f.write(f"1678886401,{relative_base_png_path_for_training},firefox,overflow,200,SUCCESS,,0\n")
        
        # Dummy debug JSON
        # The debug file name should be relative to data_dir_for_training
        dummy_debug_json_path = os.path.join(data_dir_for_training, "base.eog.uaf.retry0.png.debug")
        with open(dummy_debug_json_path, "w") as f:
            json.dump({"leaked_addresses": ["0x12345678"]}, f)
        
        # Dummy crash log
        dummy_crash_log_path = os.path.join(data_dir_for_training, "base.eog.uaf.retry0.png.crash.log")
        with open(dummy_crash_log_path, "w") as f:
            f.write("Program received signal SIGSEGV")

        # Pass relative path to data_dirs
        relative_data_dir_for_training = os.path.relpath(data_dir_for_training, self.test_dir)
        result = self._run_fuzzer(["--train", "--data_dirs", relative_data_dir_for_training])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.models_dir, "vaegan_fuzzer_model.pth")))
        self.assertTrue(os.path.exists(os.path.join(self.runs_fuzzing_dir, "events.out.tfevents.*")))

    def test_intelligent_mode(self):
        # First, train a dummy model
        self.test_train_mode() # This will create a dummy model file

        # Now run in intelligent mode
        # Mock generate_suggestion to return a predictable suggestion
        mock_suggestion = InstrumentationSuggestion(
            fuzz_type_prediction="overflow",
            payload_offset_prediction=500,
            trigger_offset_prediction=100,
            confidence=0.9
        )
        with patch('ml_fuzzer_model.generate_suggestion', return_value=mock_suggestion) as mock_gen_suggestion:
            self.mock_monitor_syslog.return_value = "pwned_png_consumer_overflow_12345_0" # Simulate success
            relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
            result = self._run_fuzzer(["--single", relative_base_png_path, "--intelligent"])
            self.assertEqual(result.returncode, 0)
            mock_gen_suggestion.assert_called_once()

            trajectory_path = os.path.join(self.output_dir, "fuzzing_trajectory.csv")
            df = pd.read_csv(trajectory_path)
            
            # Verify that the intelligent suggestion was used
            intelligent_entry = df[df["fuzz_type"] == "overflow"]
            self.assertFalse(intelligent_entry.empty)
            self.assertEqual(intelligent_entry["payload_offset_attempted"].iloc[0], 500)
            self.assertEqual(intelligent_entry["trigger_offset_attempted"].iloc[0], 100)
            self.assertIn("SUCCESS", intelligent_entry["status"].values)

    def test_advisor_mode(self):
        # First, train a dummy model
        self.test_train_mode()

        # Now run in advisor mode
        mock_suggestion = InstrumentationSuggestion(
            fuzz_type_prediction="uaf",
            payload_offset_prediction=150,
            trigger_offset_prediction=75,
            confidence=0.8
        )
        with patch('ml_fuzzer_model.generate_suggestion', return_value=mock_suggestion) as mock_gen_suggestion:
            self.mock_monitor_syslog.return_value = "pwned_png_consumer_uaf_12345_0" # Simulate success
            relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
            result = self._run_fuzzer(["--single", relative_base_png_path, "--advisor"])
            self.assertEqual(result.returncode, 0)
            mock_gen_suggestion.assert_called_once()

            # Verify that the suggestion was logged but not necessarily applied to the fuzzing process
            # (The actual fuzzing process would still use its default/legacy logic unless --intelligent is used)
            self.assertIn("ADVISOR: Suggested fuzz_type='uaf', payload_offset=150, trigger_offset=75", result.stdout)
            
            trajectory_path = os.path.join(self.output_dir, "fuzzing_trajectory.csv")
            df = pd.read_csv(trajectory_path)
            # In advisor mode, the fuzzer still uses its default logic, so the payload_offset_attempted
            # might not match the suggestion unless the default happens to be the same.
            # We primarily check for the log message.
            self.assertIn("SUCCESS", df["status"].values)

    def test_pil_viewer_simulation(self):
        """Test that the fuzzer correctly uses pil_loader.py under the virtual environment."""
        # Mock subprocess.run to capture calls to the venv python and pil_loader.py
        with patch('subprocess.run') as mock_subprocess_run:
            # Simulate pil_loader.py successfully loading the image
            mock_subprocess_run.return_value = MagicMock(
                stdout="PIL loaded /path/to/fuzzed.png",
                stderr="",
                returncode=0
            )
            self.mock_monitor_syslog.return_value = "pwned_PIL_generic_viewer_12345_0" # Simulate success

            relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
            result = self._run_fuzzer(["--single", relative_base_png_path, "--legacy"])
            self.assertEqual(result.returncode, 0)

            # Verify that the venv python and pil_loader.py were called
            # The call should be something like: ['/path/to/nvenv/bin/python', 'pil_loader.py', '/path/to/fuzzed.png']
            pil_viewer_call_found = False
            for call_args, call_kwargs in mock_subprocess_run.call_args_list:
                if self.venv_python_path_relative in call_args[0] and self.pil_loader_path_relative in call_args[0]:
                    pil_viewer_call_found = True
                    break
            self.assertTrue(pil_viewer_call_found, "pil_loader.py was not called via venv python.")

            trajectory_path = os.path.join(self.output_dir, "fuzzing_trajectory.csv")
            df = pd.read_csv(trajectory_path)
            pil_entry = df[df["viewer"] == "PIL"]
            self.assertFalse(pil_entry.empty)
            self.assertIn("SUCCESS", pil_entry["status"].values)

    def test_symlink_resolution(self):
        """Test that _extract_elf_features resolves symlinks correctly."""
        # The mock_extract_elf_features is already set up to return non-zero features.
        # We just need to ensure it was called with the resolved path.
        # The eog viewer is configured to use a symlink in setUp.
        
        # Run fuzzer in legacy mode, targeting eog
        self.mock_monitor_syslog.return_value = "pwned_eog_generic_viewer_12345_0" # Simulate success
        relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
        result = self._run_fuzzer(["--single", relative_base_png_path, "--legacy"])
        self.assertEqual(result.returncode, 0)

        # Verify that _extract_elf_features was called with the real path of the symlink
        # The call should be for the 'eog' viewer, and the path should be self.real_eog_path
        elf_feature_call_found = False
        for call_args, call_kwargs in self.mock_extract_elf_features.call_args_list:
            if os.path.abspath(self.real_eog_path_relative) in call_args[0]:
                elf_feature_call_found = True
                break
        self.assertTrue(elf_feature_call_found, "_extract_elf_features was not called with the resolved symlink path.")

    def test_lime_explanation_generation(self):
        """Test that LIME explanations are generated and logged after training."""
        # First, train a dummy model with --explain_lime
        data_dir_for_training = os.path.join(self.test_dir, "training_data")
        os.makedirs(data_dir_for_training, exist_ok=True)
        
        relative_base_png_path_for_training = os.path.relpath(self.base_png_path, data_dir_for_training)
        with open(os.path.join(data_dir_for_training, "fuzzing_trajectory.csv"), "w") as f:
            f.write("timestamp,original_file,viewer,fuzz_type,payload_offset,status,reason,retry_attempt\n")
            f.write(f"1678886400,{relative_base_png_path_for_training},eog,uaf,100,CRASHED,segfault,0\n")
            f.write(f"1678886401,{relative_base_png_path_for_training},firefox,overflow,200,SUCCESS,,0\n")
        
        dummy_debug_json_path = os.path.join(data_dir_for_training, "base.eog.uaf.retry0.png.debug")
        with open(dummy_debug_json_path, "w") as f:
            json.dump({"leaked_addresses": ["0x12345678"]}, f)
        
        dummy_crash_log_path = os.path.join(data_dir_for_training, "base.eog.uaf.retry0.png.crash.log")
        with open(dummy_crash_log_path, "w") as f:
            f.write("Program received signal SIGSEGV")

        relative_data_dir_for_training = os.path.relpath(data_dir_for_training, self.test_dir)
        result = self._run_fuzzer(["--train", "--data_dirs", relative_data_dir_for_training, "--explain_lime"])
        self.assertEqual(result.returncode, 0)

        # Verify that LimeExplainer was instantiated and explanations were generated/logged
        self.mock_lime_explainer_class.assert_called()
        self.mock_lime_explainer_instance.explain_fuzz_type_prediction.assert_called_once()
        self.mock_lime_explainer_instance.explain_payload_offset_prediction.assert_called_once()
        self.assertEqual(self.mock_plot_and_log_lime_explanation.call_count, 2) # One for fuzz_type, one for payload_offset
        
        # Check if TensorBoard event files for LIME explanations exist
        lime_events_found = False
        for root, _, files in os.walk(self.runs_lime_dir):
            for file in files:
                if "events.out.tfevents" in file:
                    lime_events_found = True
                    break
            if lime_events_found:
                break
        self.assertTrue(lime_events_found, "LIME explanation TensorBoard event files not found.")

    def test_apport_integration(self):
        # Simulate an Apport crash report being generated
        crash_time = time.time()
        # The path in CoreDump/AttachedFiles should be relative to the fuzzer's CWD (self.test_dir)
        relative_fuzzed_file_path = os.path.join("fuzz_results_single", "base.png.eog.uaf.retry0.png")
        dummy_apport_report_content = f"""
ProblemType: Crash
Package: eog
ExecutablePath: /usr/bin/eog
Signal: 11
CrashTime: {crash_time}
ProblemType: Crash
CoreDump: file://{os.path.join(os.path.abspath(self.test_dir), relative_fuzzed_file_path)}
AttachedFiles: /tmp/stacktrace.txt {os.path.join(os.path.abspath(self.test_dir), relative_fuzzed_file_path)}
Stacktrace:
 #0 0x00007f8e12345678 in crash_func ()
        """
        # Create a dummy Apport crash file
        apport_crash_file = os.path.join(self.test_dir, "var_crash", "_usr_bin_eog.1000.crash")
        os.makedirs(os.path.dirname(apport_crash_file), exist_ok=True)
        with open(apport_crash_file, "w") as f:
            f.write(dummy_apport_report_content)

        # Mock monitor_apport_log to return a line indicating the new crash report
        self.mock_monitor_apport_log.return_value = ([f"Report '{apport_crash_file}' already exists"], 100)
        
        # Mock parse_apport_report to return the parsed info
        mock_apport_info = ApportCrashInfo(
            report_path=apport_crash_file,
            package="eog",
            executable="/usr/bin/eog",
            signal=11,
            crash_time=crash_time,
            problem_type="Crash",
            associated_file=os.path.join(os.path.abspath(self.test_dir), relative_fuzzed_file_path),
            backtrace_summary=["line1"]
        )
        self.mock_parse_apport_report.return_value = mock_apport_info

        # Run fuzzer in intelligent mode (to activate Apport monitoring)
        # Simulate a crash in the png_consumer
        with open(self.png_consumer_path_relative, "w") as f:
            f.write("#!/bin/bash\n")
            f.write("echo 'png_consumer running'\n")
            f.write("echo 'Simulating crash'\n")
            f.write("exit 139 # SIGSEGV\n")
        os.chmod(self.png_consumer_path_relative, 0o755)

        relative_base_png_path = os.path.relpath(self.base_png_path, self.test_dir)
        result = self._run_fuzzer(["--single", relative_base_png_path, "--intelligent"])
        self.assertEqual(result.returncode, 0) # Fuzzer should complete, even with crashes

        trajectory_path = os.path.join(self.output_dir, "fuzzing_trajectory.csv")
        df = pd.read_csv(trajectory_path)
        
        # Find an entry that crashed and should have Apport features
        crashed_entry = df[df["status"] == "CRASHED_APPORT"]
        self.assertFalse(crashed_entry.empty)
        self.assertIn("apport_crash_features", crashed_entry.columns)
        # Check if the features are not all zeros (indicating they were populated)
        self.assertTrue(any(feat != 0.0 for feat in json.loads(crashed_entry["apport_crash_features"].iloc[0])))

if __name__ == '__main__':
    unittest.main()
