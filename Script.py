import requests # type: ignore
# ... (rest of your script) ...
import requests # type: ignore # Used to make HTTP requests to the VirusTotal API.
import argparse                # Used to build the command-line interface (CLI) (handling the -d flag).
import json                    # The requests linrary uses this to decode the API's response.
import time                    # Used to convert the 'last_analysis_date' (a number) into a readable date.

# --- CONFIGURATION ---
# (You MUST get a free API key from VirusTotal.com)
# TODO: Paste your NEW, freshly-generated API key here.
API_KEY = "YOUR_NEW_API_KEY_HERE"
# ---------------------

def check_domain_reputation(domain):
    """
    Queries the VirusTotal API for a domain report. (e.g. google.com)
    """
    # This check is to see if you're still using the placeholder. (for safety check)
    if API_KEY == "YOUR_NEW_API_KEY_HERE":
        print("Error: Please set your ThreatChecker(VirusTotal) API_KEY in the script.")
        return
    # This is an f-string. It builds the API URL by injecting the 'domain' variable.
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    # This creates a Python dictionary. VirusTotal requires your API key
    # to be sent as an 'x-apikey' header.
    headers = {
        "x-apikey": API_KEY
    }

    print(f"[*] Querying ThreatChecker for: {domain}\n")

    # This 'try...except' block is for error handling. It 'tries' to run the
    # code, but if something fails (like no internet), it will 'except' the error.
    try:

    # This is where the script actually contacts the internet.
    # It sends the GET request to the 'url' with the 'headers'.
        response = requests.get(url, headers=headers)

    # A critical line! This will automatically raise an error if the
    # response was bad (like a 401, 404, or 500 error). 
        response.raise_for_status()

    #This decodes the JSON response from VirusTotal into a Python dictionary.
        data = response.json()

    # This verifies that the response structure is what we expect.
        if 'data' in data and 'attributes' in data['data']:

    # A shortcut variable to make the code cleaner.
            attributes = data['data']['attributes']

    # Another shortcut to the 'stats' dictionary.
            stats = attributes['last_analysis_stats']
            
            print("--- VirusTotal Summary ---")
        # We fixed this earlier. The domain 'id' is in data['data'], not attributes.
            print(f"Domain: {data['data']['id']}")
            
            # Extract key stats
            # .get('key', 0) is a safe way to get data. If 'malicious' doesn't exist,
            # it returns 0 instead of crashing the script.
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            harmless = stats.get('harmless', 0)
            undetected = stats.get('undetected', 0)

            # --- Print the findings ---
            print(f"Detections: {malicious} Malicious, {suspicious} Suspicious")
            print(f"Reputation: {attributes.get('reputation', 'N/A')}")

            # The API gives a 'Unix timestamp' (a big number).
            # time.ctime() converts it to a human-readable date.
            print(f"Last Analysis: {time.ctime(attributes['last_analysis_date'])}")

            # --- The main verdict ---
            if malicious > 0 or suspicious > 0:
                print("\n[!] MALICIOUS DETECTIONS FOUND:")

                # Get the dictionary of all vendor scan results.
                analysis_results = attributes['last_analysis_results']

                # Loop through every vendor (e.g., 'Google Safebrowsing', 'Avira')
                for vendor, result in analysis_results.items():

                    # If a vendor flagged it as malicious or suspicious...
                    if result['category'] == 'malicious' or result['category'] == 'suspicious':

                        # ...print that vendor's specific finding.
                        print(f"  - {vendor}: {result['result']} ({result['category']})")
            else:
                # If no vendors flagged it.
                print("\n[+] No malicious detections found.")
                
            print("--------------------------")

        else:
            # This runs if the JSON was valid but didn't have 'data' or 'attributes'.
            print("Error: Could not parse a valid response from ThreatChecker.")


    # --- Error Handling Blocks ---
    # This block 'catches' the errors from response.raise_for_status().
    except requests.exceptions.HTTPError as errh:
        if errh.response.status_code == 404:
            print("Error: Domain not found in ThreatChecker database.")
        else:
            # For any other HTTP error (like 500 Server Error).
            print(f"Http Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        print(f"Error Connecting: {errc}") # e.g., No internet connection
    except requests.exceptions.Timeout as errt:
        print(f"Timeout Error: {errt}") # The request took too long.
    except requests.exceptions.RequestException as err:
        print(f"Something else went wrong: {err}")  # A catch-all for other errors.


# This function sets up the command-line part of the script.
def main():
    # Initializes the argument parser.
    parser = argparse.ArgumentParser(description="Check the reputation of a domain using the VirusTotal API.")
    # Defines the '-d' or '--domain' argument.
    # 'required=True' means the script won't run without it.
    parser.add_argument("-d", "--domain", required=True, help="The domain to check (e.g., example.com)")

    # This line actually reads the command line (e.g., "google.com")
    # and stores it in 'args.domain'.
    args = parser.parse_args()
    
    # This calls your main function, passing in the domain from the command line.
    check_domain_reputation(args.domain)

# This is a standard Python entry point.
# It means "Only run the main() function if this script is executed directly"
# (as opposed to being imported by another script).
if __name__ == "__main__":

    main()


