#!/usr/bin/env python3
"""
Test crash inference across multiple trajectory directories.
"""
import os
import csv
import tempfile
import sys
sys.path.insert(0, '/home/kardon/auto_rlhf')

from infect_png_fuzzer import UnifiedFuzzer

def create_sample_trajectory_with_crashes(path: str, entries: list):
    """Create sample trajectory CSV and mock crash logs."""
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
    
    # Create mock crash logs for viewers
    for viewer_name in ['eog', 'firefox', 'png_consumer']:
        viewer_dir = os.path.join(path, viewer_name)
        os.makedirs(viewer_dir, exist_ok=True)
        
        # Write a crash log for each viewer
        crash_log = os.path.join(viewer_dir, f'{viewer_name}.crash.log')
        with open(crash_log, 'w') as f:
            f.write(f"GDB output for {viewer_name}\n")
            f.write("Program received signal SIGSEGV, Segmentation fault.\n")
            f.write("0x0000000000400500 in ?? ()\n")
    
    print(f"Created {csv_file} with {len(entries)} entries and mock crash logs")
    return csv_file

def test_crash_inference():
    """Test crash inference across multiple directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        orig_cwd = os.getcwd()
        os.chdir(tmpdir)
        
        try:
            # Create entries with NOT_TRIGGERED status
            untriggered_entries = [
                {
                    "timestamp": "2026-04-01 12:00:00", "original_file": "crash_test.png", "viewer": "eog",
                    "fuzz_type": "overflow", "payload_offset_attempted": "100", "trigger_offset_attempted": "0",
                    "status": "NOT_TRIGGERED", "reason": "initial attempt", "retry_attempt": "0", "payload_validated": "0",
                    "platform": "linux", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "0", "confidence_score": "0.1"
                },
                {
                    "timestamp": "2026-04-01 12:01:00", "original_file": "crash_test.png", "viewer": "firefox",
                    "fuzz_type": "uaf", "payload_offset_attempted": "200", "trigger_offset_attempted": "0",
                    "status": "UNKNOWN", "reason": "pending", "retry_attempt": "1", "payload_validated": "0",
                    "platform": "linux", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "0", "confidence_score": "0.05"
                }
            ]
            create_sample_trajectory_with_crashes('fuzz_results_single', untriggered_entries)
            
            untriggered_entries_2 = [
                {
                    "timestamp": "2026-04-01 12:30:00", "original_file": "crash_test2.png", "viewer": "png_consumer",
                    "fuzz_type": "double_free", "payload_offset_attempted": "150", "trigger_offset_attempted": "0",
                    "status": "UNTRIGGERED", "reason": "no effect", "retry_attempt": "0", "payload_validated": "0",
                    "platform": "linux_aarch64", "fitting_payload_addr": "", "fitting_offsets": "", "success_label": "0", "confidence_score": "0.15"
                }
            ]
            create_sample_trajectory_with_crashes('infected_media_unified_crash_test', untriggered_entries_2)
            
            # Create fuzzer and test crash inference
            fuzzer = UnifiedFuzzer("crash_test", use_advisor=False, use_intelligent=False, use_legacy=False)
            
            print("\n=== Starting Crash Inference Test ===\n")
            result = fuzzer._reconcile_all_previous_runs()
            
            print("\n=== Test Results ===")
            print(f"Directories found: {result.get('all_dirs', [])}")
            print(f"Inferred crashed trajectories to retry: {result.get('inferred_trajectories_to_retry', 0)}")
            print(f"Updated entries status: {result.get('total_reconciled_updates', 0)}")
            
            # Verify the CSV was updated with CRASHED_INFERRED status
            for traj_dir in ['fuzz_results_single', 'infected_media_unified_crash_test']:
                csv_path = os.path.join(traj_dir, 'fuzzing_trajectory.csv')
                if os.path.exists(csv_path):
                    with open(csv_path, 'r') as f:
                        reader = csv.DictReader(f)
                        crashed_count = 0
                        for row in reader:
                            if row.get('status') == 'CRASHED_INFERRED':
                                crashed_count += 1
                        print(f"✅ {traj_dir}: {crashed_count} entries updated to CRASHED_INFERRED")
            
            if result.get('inferred_trajectories_to_retry', 0) > 0:
                print(f"\n✅ Crash inference test PASSED - {result['inferred_trajectories_to_retry']} trajectories marked for retry")
                return True
            else:
                print("\n⚠️  Warning: Expected inferred trajectories but found none")
                return False
            
        except Exception as e:
            print(f"\n❌ Test FAILED: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            os.chdir(orig_cwd)

if __name__ == '__main__':
    success = test_crash_inference()
    sys.exit(0 if success else 1)
