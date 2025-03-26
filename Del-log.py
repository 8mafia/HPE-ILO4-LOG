import json
import requests
import time
from concurrent.futures import ThreadPoolExecutor
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuration
CONFIG_FILE = "config.json"
IP_LIST_FILE = "ip_list.txt"
TIMEOUT = 2  # 2 seconds timeout
MAX_WORKERS = 10  # Process 10 servers at a time

def load_config():
    """Load configuration from config.json"""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def load_ip_list():
    """Load IP list from file"""
    try:
        with open(IP_LIST_FILE, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error loading IP list: {e}")
        return []

def login_ilo(ip, username, password):
    """Login to iLO and return session ID and session URI"""
    url = f"https://{ip}/rest/v1/SessionService/Sessions"
    headers = {'Content-Type': 'application/json'}
    payload = {
        "UserName": username,
        "Password": password
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code == 201:
            session_id = response.headers.get('X-Auth-Token')
            response_json = response.json()
            
            # Try to get session URI from response body (OdataId or @odata.id)
            session_uri = response_json.get('OdataId', response_json.get('@odata.id'))
            
            # If session URI is not in the body, extract it from the Link or Location header
            if not session_uri:
                # Check the Link header
                link_header = response.headers.get('Link')
                if link_header:
                    # Extract the URI from the Link header (format: <URI>; rel=self)
                    link_parts = link_header.split(';')
                    if len(link_parts) > 0:
                        session_uri = link_parts[0].strip().lstrip('<').rstrip('>')
                
                # If still not found, try the Location header
                if not session_uri:
                    location_header = response.headers.get('Location')
                    if location_header:
                        # Extract the URI part from the Location header
                        session_uri = location_header.replace(f"https://{ip}", "")
            
            if not session_id or not session_uri:
                print(f"Login failed for {ip}: Missing session ID or URI in response")
                print(f"Response Headers: {response.headers}")
                print(f"Response Body: {response_json}")
                return None, None
            
            print(f"Login successful for {ip}")
            return session_id, session_uri
        else:
            print(f"Login failed for {ip}: {response.status_code} - {response.text}")
            return None, None
    except requests.Timeout:
        print(f"Login timeout for {ip}")
        return None, None
    except requests.ConnectionError:
        print(f"Connection error for {ip}: Unable to connect")
        return None, None
    except Exception as e:
        print(f"Login error for {ip}: {e}")
        return None, None

def logout_ilo(ip, session_id, session_uri):
    """Logout from iLO session"""
    if not session_id or not session_uri:
        print(f"Cannot logout from {ip}: Missing session ID or URI")
        return
    
    url = f"https://{ip}{session_uri}"
    headers = {'X-Auth-Token': session_id}
    
    try:
        response = requests.delete(url, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code == 200:
            print(f"Logged out successfully from {ip}")
        else:
            print(f"Logout failed for {ip}: {response.status_code} - {response.text}")
    except requests.Timeout:
        print(f"Logout timeout for {ip}")
    except Exception as e:
        print(f"Logout error for {ip}: {e}")

def clear_iml(ip, session_id):
    """Clear the Integrated Management Log (IML)"""
    url = f"https://{ip}/rest/v1/Systems/1/LogServices/IML/Actions/LogService.ClearLog"
    headers = {'X-Auth-Token': session_id, 'Content-Type': 'application/json'}
    payload = {}  # Empty JSON payload to avoid MalformedJSON error
    
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code in [200, 204]:
            print(f"Cleared Integrated Management Log on {ip} successfully")
        else:
            print(f"Failed to clear Integrated Management Log on {ip}: {response.status_code} - {response.text}")
    except requests.Timeout:
        print(f"Clear IML operation timeout for {ip}")
    except Exception as e:
        print(f"Error clearing Integrated Management Log on {ip}: {e}")

def clear_ilo_event_log(ip, session_id):
    """Clear the iLO Event Log"""
    url = f"https://{ip}/rest/v1/Managers/1/LogServices/IEL/Actions/LogService.ClearLog"
    headers = {'X-Auth-Token': session_id, 'Content-Type': 'application/json'}
    payload = {}  # Empty JSON payload to avoid MalformedJSON error
    
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False, timeout=TIMEOUT)
        if response.status_code in [200, 204]:
            print(f"Cleared iLO Event Log on {ip} successfully")
        else:
            print(f"Failed to clear iLO Event Log on {ip}: {response.status_code} - {response.text}")
    except requests.Timeout:
        print(f"Clear iLO Event Log operation timeout for {ip}")
    except Exception as e:
        print(f"Error clearing iLO Event Log on {ip}: {e}")

def process_server(ip, login_username, login_password):
    """Process a single server"""
    print(f"Processing {ip}")
    # Login and get both session ID and session URI
    session_id, session_uri = login_ilo(ip, login_username, login_password)
    if session_id:
        try:
            # Clear the Integrated Management Log
            clear_iml(ip, session_id)
            # Clear the iLO Event Log
            clear_ilo_event_log(ip, session_id)
        finally:
            # Always attempt to logout, even if log clearing fails
            logout_ilo(ip, session_id, session_uri)
    else:
        print(f"Skipping log clearing for {ip} due to login failure")

def main():
    # Load configuration
    config = load_config()
    if not config:
        return
    
    login_username = config.get('login_username')
    login_password = config.get('login_password')
    
    if not all([login_username, login_password]):
        print("Missing required configuration parameters")
        return
    
    # Load IP list
    ip_list = load_ip_list()
    if not ip_list:
        print("No IPs found in list")
        return
    
    # Process servers in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(
                process_server,
                ip,
                login_username,
                login_password
            )
            for ip in ip_list
        ]
        
        # Wait for all tasks to complete
        for future in futures:
            try:
                future.result()
            except Exception as e:
                print(f"Thread execution error: {e}")
    
    print("\nProcessing complete")

if __name__ == "__main__":
    start_time = time.time()
    main()
    print(f"Total execution time: {time.time() - start_time:.2f} seconds")
