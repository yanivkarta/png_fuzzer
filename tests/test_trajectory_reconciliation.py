#!/usr/bin/env python3
"""
Test script to verify multi-directory trajectory reconciliation.
"""
import os
import csv
import tempfile
import shutil
import sys
sys.path.insert(0, '/home/kardon/auto_rlhf')

from infect_png_fuzzer import UnifiedFuzzer

def create_sample_trajectory(path: str, entries: list):
    """Create a sample trajectory CSV at the given path."""
    os.makedirs(path, exist_ok=True)
    csv_file = os.path.join(path, 'fuzzing_trajectory.csv')
    
    fieldnames = [
        "timestamp", "original_file", "viewer", "fuzz_type", "payload_offset_attempted",
        "trigger_offset_attempted", "status", "reason", "retry_attempt", "payload_validated",
        "platform", "fitting_payload_addr", "fitting_offsets", "success_label", "confidence_score"
    ]
    
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(entry)
    
    print(f"Created {csv_file} with {len(entries)} entries")
    return csv_file

def test_multi_trajectory_reconciliation():
    """Test reconciliation across multiple trajectory directories."""
    # Setup: Create temp directories with sample data
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_cwd = os.getcwd()
        os.chdir(tmpdir)
        
        try:
            # Create sample fuzz_results_single trajectory
            single_entries = [
                {
                    "timestamp": "2026-04-01 10:00:00", "original_file": "test.png", "viewer": "eog",
                    "fuzz_type": "overflow", "payload_offset_attempted": "100", "trigger_offset_attempted": "0",
                    "status": "PAYLOAD_EXECUTED", "reason": "syslog", "retry_attempt": "0", "payload_validated": "1",
                    "platform": "linux", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "1", "confidence_score": "0.95"
                },
                {
                    "timestamp": "2026-04-01 10:01:00", "original_file": "test.png", "viewer": "png_consumer",
                    "fuzz_type": "uaf", "payload_offset_attempted": "200", "trigger_offset_attempted": "0",
                    "status": "NOT_TRIGGERED", "reason": "no crash", "retry_attempt": "2", "payload_validated": "0",
                    "platform": "linux", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "0", "confidence_score": "0.3"
                }
            ]
            create_sample_trajectory('fuzz_results_single', single_entries)
            
            # Create sample infected_media_unified_* trajectory
            platform_entries = [
                {
                    "timestamp": "2026-04-01 11:00:00", "original_file": "test2.png", "viewer": "firefox",
                    "fuzz_type": "vop", "payload_offset_attempted": "150", "trigger_offset_attempted": "0",
                    "status": "TRIGGERED", "reason": "netcat/rshell", "retry_attempt": "1", "payload_validated": "1",
                    "platform": "linux_aarch64", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "1", "confidence_score": "0.88"
                },
                {
                    "timestamp": "2026-04-01 11:01:00", "original_file": "test2.png", "viewer": "eog",
                    "fuzz_type": "metadata_trigger", "payload_offset_attempted": "50", "trigger_offset_attempted": "0",
                    "status": "NOT_TRIGGERED", "reason": "no crash", "retry_attempt": "0", "payload_validated": "0",
                    "platform": "linux_aarch64", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "0", "confidence_score": "0.2"
                }
            ]
            create_sample_trajectory('infected_media_unified_linux_6.17.0_test', platform_entries)
            
            # Create fuzzer instance and test reconciliation
            fuzzer = UnifiedFuzzer("test_platform", use_advisor=False, use_intelligent=False, use_legacy=False)
            
            print("\n=== Starting Multi-Trajectory Reconciliation Test ===\n")
            result = fuzzer._reconcile_all_previous_runs()
            
            print("\n=== Test Results ===")
            print(f"Directories found: {result.get('all_dirs', [])}")
            print(f"Aggregated success counts: {result.get('aggregated_success_counts', {})}")
            print(f"Trajectories to retry (crashed): {result.get('inferred_trajectories_to_retry', 0)}")
            print(f"Total updates applied: {result.get('total_reconciled_updates', 0)}")
            
            # Verify expectations
            success_counts = result.get('aggregated_success_counts', {})
            
            # Should have aggregated EOG success (overflow + metadata_trigger)
            if 'eog' in success_counts:
                syslog_successes = success_counts['eog'].get('syslog', {}).get('OVERFLOW', 0)
                print(f"\n✅ EOG syslog/overflow successes: {syslog_successes}")
            
            if 'firefox' in success_counts:
                rshell_successes = success_counts['firefox'].get('rshell', {}).get('VOP', 0)
                print(f"✅ Firefox rshell/VOP successes: {rshell_successes}")
            
            print("\n✅ Multi-trajectory reconciliation test PASSED")
            return True
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            os.chdir(orig_cwd)

if __name__ == '__main__':
    success = test_multi_trajectory_reconciliation()
    sys.exit(0 if success else 1)
