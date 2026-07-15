import subprocess
import sys
import time
import json
import urllib.request
import urllib.parse
import asyncio
import websockets

async def listen_ws(duration):
    print("Connecting to WebSocket...")
    flows_received = []
    try:
        async with websockets.connect("ws://127.0.0.1:8000/ws") as websocket:
            print("WebSocket Connected! Listening for flows...")
            start_time = time.time()
            while time.time() - start_time < duration:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    msg_data = json.loads(message)
                    print(f"WS Event: {msg_data.get('event')} | Data Keys: {list(msg_data.get('data', {}).keys())}")
                    if msg_data.get("event") == "new_flow":
                        flows_received.append(msg_data["data"])
                except asyncio.TimeoutError:
                    continue
    except Exception as e:
        print(f"WebSocket listening encountered error: {e}")
    return flows_received

def trigger_capture():
    print("Fetching interfaces...")
    try:
        req = urllib.request.urlopen("http://127.0.0.1:8000/api/interfaces")
        ifaces = json.loads(req.read())
        print(f"Available interfaces: {len(ifaces)}")
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        return None

    # Choose first active-looking interface or Wi-Fi
    target_iface = None
    for iface in ifaces:
        if "Wi-Fi" in iface['description'] or "Wi-Fi" in iface['name']:
            target_iface = iface['pcap_name']
            break
    if not target_iface and ifaces:
        target_iface = ifaces[0]['pcap_name']

    if not target_iface:
        print("No suitable interface found to sniff.")
        return None

    print(f"Selected sniffer target: {target_iface}")
    url = f"http://127.0.0.1:8000/api/capture/start?interface={urllib.parse.quote(target_iface)}"
    print(f"POST request: {url}")
    try:
        req = urllib.request.Request(url, method="POST")
        res = urllib.request.urlopen(req)
        print(f"Start Capture Response: {res.read().decode()}")
        return target_iface
    except Exception as e:
        print(f"Error triggering start capture: {e}")
        return None

def stop_capture():
    print("Stopping capture...")
    try:
        req = urllib.request.Request("http://127.0.0.1:8000/api/capture/stop", method="POST")
        res = urllib.request.urlopen(req)
        print(f"Stop Capture Response: {res.read().decode()}")
    except Exception as e:
        print(f"Error stopping capture: {e}")

async def main():
    print("Spawning Uvicorn backend process...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.api.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PYTHONPATH": "."}
    )
    
    # Wait for server to bind
    time.sleep(5)

    try:
        health_req = urllib.request.urlopen("http://127.0.0.1:8000/health")
        print(f"Backend Health check: {health_req.read().decode()}")
    except Exception as e:
        print(f"Backend is not healthy: {e}")
        proc.terminate()
        return

    # Trigger sniffer
    iface = trigger_capture()
    if not iface:
        print("Sniffer trigger failed. Terminating.")
        proc.terminate()
        return

    # Generate some HTTP traffic in the background to guarantee flow assemblies
    print("Generating simulated web traffic (fetching public pages)...")
    def fetch_web():
        time.sleep(2)
        urls = ["https://www.google.com", "https://www.wikipedia.org", "https://www.github.com"]
        for u in urls:
            try:
                print(f"Fetching {u} to generate packet exchanges...")
                urllib.request.urlopen(u, timeout=2.0)
            except Exception:
                pass
            time.sleep(1.5)
            
    loop = asyncio.get_running_loop()
    loop.run_in_executor(None, fetch_web)

    # Listen to WebSocket flows
    print("Starting flow WebSocket listener...")
    captured_flows = await listen_ws(20)

    # Stop capture
    stop_capture()

    # Shutdown backend process
    print("Terminating server...")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()

    print(f"\nSummary: Captured {len(captured_flows)} flows during this test run.")
    if len(captured_flows) > 0:
        print("TEST PASSED: Live capture and WebSocket streaming is fully functional!")
    else:
        print("TEST FAILED: Sniffer started, but no flows were assembled. Verify driver permissions.")

if __name__ == "__main__":
    asyncio.run(main())
