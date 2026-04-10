#!/usr/bin/env python3
"""
Test script for enhanced crash monitor with Crashpad support.
"""
import os
import tempfile
import sys
sys.path.insert(0, '/home/kardon/auto_rlhf')

from crash_monitor import (
    CrashpadDumpInfo, parse_crashpad_dump, copy_crashpad_dump_for_analysis,
    _extract_executable_from_dump_path, monitor_crashpad_dumps,
    detect_vop_trap_crashpad, export_crashpad_analysis_json
)

def create_mock_minidump(path: str) -> str:
    """Create a mock minidump file for testing."""
    dump_path = os.path.join(path, "firefox_mock.dmp")
    
    # Create a minimal mock dump (just some binary data)
    with open(dump_path, 'wb') as f:
        # Write some mock minidump header-like data
        f.write(b'MDMP')  # Minidump signature
        f.write(b'\x00' * 100)  # Padding
    
    return dump_path

def test_crashpad_functionality():
    """Test basic Crashpad dump handling functionality."""
    print("=== Testing Crashpad Dump Functionality ===\n")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Test executable extraction
        test_paths = [
            "/home/user/.mozilla/firefox/Crash Reports/pending/bp-12345678.dmp",
            "/var/crashpad/chrome.dmp",
            "/tmp/eog_crash.dmp"
        ]
        
        for path in test_paths:
            exe = _extract_executable_from_dump_path(path)
            print(f"Path: {path} -> Executable: {exe}")
        
        # Test dump copying
        mock_dump = create_mock_minidump(tmpdir)
        copied = copy_crashpad_dump_for_analysis(mock_dump)
        print(f"\nOriginal dump: {mock_dump}")
        print(f"Copied dump: {copied}")
        assert os.path.exists(copied), "Dump was not copied successfully"
        
        # Test dump monitoring
        dumps, new_time = monitor_crashpad_dumps(0.0, [tmpdir])
        print(f"\nFound {len(dumps)} dumps in {tmpdir}")
        assert len(dumps) > 0, "Mock dump was not detected"
        
        # Test basic dump parsing (will use fallback since no minidump_stackwalk)
        dump_info = parse_crashpad_dump(mock_dump)
        if dump_info:
            print(f"\nParsed dump info:")
            print(f"  Executable: {dump_info.executable}")
            print(f"  Registers: {len(dump_info.registers)}")
            print(f"  Backtrace frames: {len(dump_info.backtrace)}")
            
            # Test VOP detection on mock data
            dump_info.registers = {'x0': 0x1000, 'q0': 0x2000, 'd1': 0x1500}
            dump_info.backtrace = ['fmov d0, x1', 'ldr q0, [x2]']
            detect_vop_trap_crashpad(dump_info)
            
            print(f"  VOP trap detected: {dump_info.vop_trap}")
            print(f"  Trap details: {len(dump_info.trap_details)}")
            
            # Test JSON export
            json_path = "test_crashpad_analysis.json"
            export_crashpad_analysis_json([dump_info], json_path)
            print(f"  Analysis exported to: {json_path}")
            assert os.path.exists(json_path), "Analysis JSON was not created"
        
        print("\n✅ All Crashpad functionality tests passed!")
        return True

if __name__ == '__main__':
    success = test_crashpad_functionality()
    sys.exit(0 if success else 1)
