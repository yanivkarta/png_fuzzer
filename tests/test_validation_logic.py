import os
import subprocess
import time
import json
import csv
import shutil
import logging
from infect_png_fuzzer import monitor_syslog, verify_payload_execution, generate_base_png, fuzz_single_file, fuzz_platform

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_syslog_monitoring():
    logger.info("Testing syslog monitoring...")
    unique_id = f"test_val_{int(time.time())}"
    # Trigger a log entry
    subprocess.run(["logger", unique_id], check=True)
    
    # Check if we can find it
    found = monitor_syslog(unique_id, timeout=5)
    if found:
        logger.info(f"SUCCESS: Found log entry: {found}")
    else:
        logger.error("FAILURE: Could not find log entry in syslog. Check permissions (must be in 'adm' group).")
    return found is not None

def test_fail_fast_logic():
    logger.info("Testing fail-fast logic...")
    source_dir = "test_samples_failfast"
    if os.path.exists(source_dir): shutil.rmtree(source_dir)
    os.makedirs(source_dir)
    generate_base_png(os.path.join(source_dir, "test1.png"))
    
    # Run fuzz_platform which now has pre-flight check
    # We expect it to try weaknesses until one works or it fails
    platform_id = "test_platform"
    fuzz_platform(source_dir, platform_id)
    
    target_dir = f"infected_media_{platform_id}"
    if os.path.exists(f"{target_dir}_SUCCESS"):
        target_dir = f"{target_dir}_SUCCESS"
        
    db_path = os.path.join(target_dir, "fuzzing_trajectory.csv")
    
    if os.path.exists(db_path):
        logger.info(f"SUCCESS: Trajectory database created at {db_path}")
        with open(db_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            for row in rows:
                logger.info(f"File: {row['file']}, Status: {row['status']}, Payload Validated: {row.get('payload_validated')}")
    else:
        logger.error("FAILURE: Trajectory database not created. Pre-flight might have failed.")

def test_single_file_fuzzing():
    logger.info("Testing single file fuzzing overhaul...")
    test_file = "test_single.png"
    generate_base_png(test_file)
    
    platform_id = "test_platform_single"
    results = fuzz_single_file(test_file, platform_id)
    
    if os.path.exists("potential_weaknesses.json"):
        logger.info("SUCCESS: potential_weaknesses.json created.")
        with open("potential_weaknesses.json", "r") as f:
            data = json.load(f)
            logger.info(f"Found {len(data)} viable weaknesses.")
    else:
        logger.error("FAILURE: potential_weaknesses.json not created.")
        
    if os.path.exists(test_file): os.remove(test_file)

def test_preflight_failure_fallback():
    logger.info("Testing pre-flight failure fallback...")
    source_dir = "test_samples_fallback"
    if os.path.exists(source_dir): shutil.rmtree(source_dir)
    os.makedirs(source_dir)
    
    # Create a PNG that might cause some weaknesses to fail but others to pass
    generate_base_png(os.path.join(source_dir, "fallback_test.png"))
    
    platform_id = "test_fallback_platform"
    fuzz_platform(source_dir, platform_id)
    
    target_dir = f"infected_media_{platform_id}"
    if os.path.exists(f"{target_dir}_SUCCESS") or os.path.exists(target_dir):
        logger.info("SUCCESS: Fallback test completed execution.")
    else:
        logger.error("FAILURE: Fallback test did not produce output.")

if __name__ == "__main__":
    if test_syslog_monitoring():
        test_fail_fast_logic()
        test_single_file_fuzzing()
        test_preflight_failure_fallback()
    else:
        logger.warning("Skipping further tests because syslog monitoring failed.")
