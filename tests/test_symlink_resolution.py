import unittest
import os
import sys
import subprocess
import shutil
from unittest.mock import patch, MagicMock, call # Import call for explicit mock assertions

# Add the directory containing data_processor.py and infect_png_fuzzer.py to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

class TestSymlinkResolution(unittest.TestCase):

    def setUp(self):
        self.test_dir = os.path.abspath("test_temp_symlink") # Make test_dir absolute
        
        # Ensure a clean test directory for each test run
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir) # Use rmtree for complete cleanup
        os.makedirs(self.test_dir, exist_ok=True)

        self.dummy_executable_path = os.path.join(self.test_dir, "dummy_exec")
        self.symlink_path = os.path.join(self.test_dir, "symlink_to_exec")
        self.broken_symlink_path = os.path.join(self.test_dir, "broken_symlink")
        self.non_executable_path = os.path.join(self.test_dir, "non_exec_file")

        # Create a dummy executable file
        with open(self.dummy_executable_path, "w") as f:
            f.write("#!/bin/bash\necho 'dummy exec'")
        os.chmod(self.dummy_executable_path, 0o755)

        # Create a symbolic link to the dummy executable
        os.symlink(self.dummy_executable_path, self.symlink_path)

        # Create a broken symbolic link
        os.symlink("non_existent_target", self.broken_symlink_path)

        # Create a non-executable file
        with open(self.non_executable_path, "w") as f:
            f.write("just a text file")
        os.chmod(self.non_executable_path, 0o644)

        # Import data_processor and infect_png_fuzzer after setting up paths
        import data_processor
        import infect_png_fuzzer
        self.data_processor = data_processor
        self.infect_png_fuzzer = infect_png_fuzzer

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir) # Use rmtree for complete cleanup

    def test_extract_elf_features_with_symlink(self):
        """
        Test _extract_elf_features with a symbolic link.
        It should resolve the symlink and extract features from the real executable.
        """
        # Mock subprocess.run for readelf calls within _extract_elf_features
        with patch('subprocess.run') as mock_subprocess_run:
            # Configure mock to return dummy output for readelf -h and -S
            mock_subprocess_run.side_effect = [
                MagicMock(stdout="""
ELF Header:
  Class:                             ELF64
  Machine:                           AArch64
  Entry point address:               0x400000
Type:                              EXEC (Executable file)
""", stderr="", returncode=0),
                MagicMock(stdout="""
Section Headers:
  [Nr] Name              Type            Address          Off    Size   EntSize  Flags  Link  Info  Align
  [ 1] .text             PROGBITS        0000000000001000 001000 000010 000000   AX     0     0     16
  [ 2] .symtab           SYMTAB          0000000000002000 002000 000020 000000   S      0     0     8
""", stderr="", returncode=0),
                MagicMock(stdout="""
Symbol table '.symtab' contains 2 entries:
""", stderr="", returncode=0),
                MagicMock(stdout="""
Dynamic section contains 0 entries:
""", stderr="", returncode=0)
            ]
            
            # Call _extract_elf_features with the symlink path
            features = self.data_processor._extract_elf_features(self.symlink_path)
            
            # Assert that readelf was called with the resolved path
            # The first call to readelf -h should be with the real path
            expected_readelf_path = os.path.realpath(self.symlink_path)
            mock_subprocess_run.assert_any_call(call(['readelf', '-h', expected_readelf_path], capture_output=True, text=True, check=True))
            
            # Assert that features are extracted (not all zeros)
            self.assertGreater(sum(features), 0, "Features should be extracted from the real executable")
            self.assertEqual(len(features), self.data_processor.ELF_FEATURE_VECTOR_SIZE)

    def test_extract_elf_features_with_broken_symlink(self):
        """
        Test _extract_elf_features with a broken symbolic link.
        It should detect that the resolved path does not exist and return zeros.
        """
        # Mock subprocess.run to ensure it's not called if os.path.exists returns False
        with patch('subprocess.run') as mock_subprocess_run:
            features = self.data_processor._extract_elf_features(self.broken_symlink_path)
            
            # Assert that subprocess.run was NOT called
            mock_subprocess_run.assert_not_called()
            
            # Assert that features are all zeros
            self.assertTrue(all(f == 0.0 for f in features), "Features should be all zeros for a broken symlink")
            self.assertEqual(len(features), self.data_processor.ELF_FEATURE_VECTOR_SIZE)

    def test_analyze_crash_with_resolved_path(self):
        """
        Test analyze_crash function to ensure it resolves the viewer path.
        """
        gdb_output = """
Program received signal SIGSEGV, Segmentation fault.
#0  0x0000000000401234 in crash_func ()
#1  0x0000000000401250 in main ()
=> 0x0000000000401234 <crash_func+0>:    mov    x0, x1
"""
        viewer_name = "dummy_viewer"
        viewer_cmd = [self.symlink_path, "some_arg"] # Pass the symlink as viewer_cmd[0]

        analysis = self.infect_png_fuzzer.analyze_crash(gdb_output, viewer_name, viewer_cmd)
        
        # Assert that the resolved_viewer_path is correctly set to the real path
        self.assertEqual(analysis["resolved_viewer_path"], os.path.abspath(self.dummy_executable_path))
        self.assertEqual(analysis["viewer"], viewer_name) # Check that viewer name is preserved
        self.assertIsNotNone(analysis["faulting_instruction"]) # Ensure crash details are extracted
        self.assertGreater(len(analysis["backtrace_summary"]), 0) # Ensure backtrace is present

    def test_analyze_crash_with_non_symlink_path(self):
        """
        Test analyze_crash with a direct path (not a symlink).
        It should still resolve to itself.
        """
        gdb_output = """
Program received signal SIGSEGV, Segmentation fault.
#0  0x0000000000401234 in crash_func ()
#1  0x0000000000401250 in main ()
=> 0x0000000000401234 <crash_func+0>:    mov    x0, x1
"""
        viewer_name = "dummy_viewer"
        viewer_cmd = [self.dummy_executable_path, "some_arg"]

        analysis = self.infect_png_fuzzer.analyze_crash(gdb_output, viewer_name, viewer_cmd)
        
        # Assert that the resolved_viewer_path is correctly set to the original path
        self.assertEqual(analysis["resolved_viewer_path"], os.path.abspath(self.dummy_executable_path))
        self.assertEqual(analysis["viewer"], viewer_name) # Check that viewer name is preserved
        self.assertIsNotNone(analysis["faulting_instruction"]) # Ensure crash details are extracted
        self.assertGreater(len(analysis["backtrace_summary"]), 0) # Ensure backtrace is present

    def test_analyze_crash_with_non_existent_viewer_cmd(self):
        """
        Test analyze_crash with a non-existent viewer command path.
        resolved_viewer_path should be None.
        """
        gdb_output = """
Program received signal SIGSEGV, Segmentation fault.
#0  0x0000000000401234 in crash_func ()
#1  0x0000000000401250 in main ()
=> 0x0000000000401234 <crash_func+0>:    mov    x0, x1
"""
        viewer_name = "dummy_viewer"
        non_existent_cmd_path = os.path.join(self.test_dir, "non_existent_cmd")
        non_existent_cmd = [non_existent_cmd_path, "some_arg"]

        analysis = self.infect_png_fuzzer.analyze_crash(gdb_output, viewer_name, non_existent_cmd)
        
        self.assertIsNone(analysis["resolved_viewer_path"])
        self.assertEqual(analysis["viewer"], viewer_name) # Check that viewer name is preserved
        self.assertIsNotNone(analysis["faulting_instruction"]) # Ensure crash details are extracted
        self.assertGreater(len(analysis["backtrace_summary"]), 0) # Ensure backtrace is present

if __name__ == '__main__':
    unittest.main()
