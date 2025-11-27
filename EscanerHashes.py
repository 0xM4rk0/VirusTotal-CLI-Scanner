#!/usr/bin/env python3

import requests
import base64
import json

print(r'''

██╗   ██╗██╗██████╗ ██╗   ██╗███████╗                   
██║   ██║██║██╔══██╗██║   ██║██╔════╝                   
██║   ██║██║██████╔╝██║   ██║███████╗                   
╚██╗ ██╔╝██║██╔══██╗██║   ██║╚════██║                   
 ╚████╔╝ ██║██║  ██║╚██████╔╝███████║                   
  ╚═══╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                   
                                                        
████████╗ ██████╗ ████████╗ █████╗ ██╗                  
╚══██╔══╝██╔═══██╗╚══██╔══╝██╔══██╗██║                  
   ██║   ██║   ██║   ██║   ███████║██║                  
   ██║   ██║   ██║   ██║   ██╔══██║██║                  
   ██║   ╚██████╔╝   ██║   ██║  ██║███████╗             
   ╚═╝    ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝             
                                                        
 ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗ 
██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝
██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗
╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║
 ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

''')


# ------------------------------
# Utility printing function
# ------------------------------
def print_result(data):
    """
    Extracts and prints the detection statistics from a VirusTotal API response.
    """

    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
    except KeyError:
        print("No analysis statistics available.\n")
        return

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())

    if malicious > 0:
        status = "MALICIOUS"
    elif suspicious > 0:
        status = "SUSPICIOUS"
    else:
        status = "CLEAN"

    print(f"Resource status: {status} ({malicious}/{total} engines flagged it)\n")

    return {"status": status, "malicious": malicious, "total": total}


# ------------------------------
# Save result to JSON file
# ------------------------------
def save_result(result, filename="results.json"):
    """
    Appends analysis results to a JSON file.
    """
    try:
        with open(filename, "a") as f:
            json.dump(result, f)
            f.write("\n")
    except Exception as e:
        print(f"Could not save the result: {e}")


# ------------------------------
# VirusTotal Request Wrapper
# ------------------------------
def vt_request(endpoint, api_key):
    """
    Sends a GET request to the VirusTotal API with the user's API key.
    """
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(endpoint, headers=headers)

        if response.status_code == 404:
            print("Resource not found on VirusTotal.\n")
            return None

        response.raise_for_status()
        return response.json()

    except requests.exceptions.RequestException as e:
        print(f"Request error: {e}\n")
        return None


# ------------------------------
# Check HASH
# ------------------------------
def check_hash(api_key):
    while True:
        hash_value = input("Enter a hash (MD5/SHA1/SHA256) or '0' to exit: ")

        if hash_value == "0":
            return

        if len(hash_value) not in (32, 40, 64):
            print("Invalid hash format.\n")
            continue

        endpoint = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        data = vt_request(endpoint, api_key)

        if data:
            result = print_result(data)
            save_result(result)
            input("Press Enter to continue...")
            break


# ------------------------------
# Check URL
# ------------------------------
def check_url(api_key):
    while True:
        url = input("Enter a URL (http/https) or '0' to exit: ")

        if url == "0":
            return

        # According to VirusTotal, URLs must be base64url encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        data = vt_request(endpoint, api_key)

        if data:
            result = print_result(data)
            save_result(result)
            input("Press Enter to continue...")
            break


# ------------------------------
# Check IP
# ------------------------------
def check_ip(api_key):
    while True:
        ip = input("Enter an IP address or '0' to exit: ")

        if ip == "0":
            return

        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        data = vt_request(endpoint, api_key)

        if data:
            result = print_result(data)
            save_result(result)
            input("Press Enter to continue...")
            break


# ------------------------------
# Main Menu
# ------------------------------
def main():
    api_key = input("Enter your VirusTotal API key: ")

    while True:
        print("\nSelect an option:")
        print(" [1] Analyze Hash")
        print(" [2] Analyze URL")
        print(" [3] Analyze IP Address")
        print(" [0] Exit")

        option = input("--> ")

        if option == "1":
            check_hash(api_key)
        elif option == "2":
            check_url(api_key)
        elif option == "3":
            check_ip(api_key)
        elif option == "0":
            print("Exiting...")
            break
        else:
            print("Invalid option.\n")


if __name__ == "__main__":
    main()
