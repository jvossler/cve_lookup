"""
CVE Data Fetcher Copyright (C) 2023  https://github.com/jvossler

This script is designed to fetch and compile information about specified Common 
Vulnerabilities and Exposures (CVE) from multiple authoritative sources, including 
CISA KEV, NIST, and MITRE CVE Repository. It allows users to input a CVE number and 
automatically gathers relevant data, creating a dated directory for organized storage 
of the results.

Key Features:
- Fetches CVE data from CISA KEV catalog and NIST database.
- Retrieves CVE file from the MITRE CVE Repository hosted on GitHub.
- Organizes fetched data into JSON files within a specifically named directory based 
    on the CVE number and current date.
- Handles dependencies by ensuring the 'requests' package is installed.
- Provides user-friendly command-line interface for inputting CVE numbers.

Usage:
    python script_name.py CVE-2023-1234

Note: This script requires internet access to fetch data from the specified APIs and repositories.

Author: https://github.com/jvossler
Created Date: 10/26/2023
Last Modified Date: 10/30/2023
Version: Version 7.4
License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007 <https://www.gnu.org/licenses/gpl.html>
Copyright (C) 2023

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>
or <https://www.gnu.org/licenses/gpl.html>.

The author can be reached via email at jvossler@proton.me.

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; for more details see:
<https://www.gnu.org/licenses/gpl.html>.
License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007
"""

import sys
import os
import subprocess
import importlib
import json
from datetime import datetime

def main():
    """
    Main function to execute the CVE search program.

    This function sets up command line argument parsing and initiates the process of downloading
    and writing information about specified CVE from various sources including CISA KEV and NIST.

    The program expects a single command line argument which is the CVE number.

    Usage:
        python script_name.py CVE-2023-1234
    """

    parser = argparse.ArgumentParser(description="CVE Search Program")
    parser.add_argument("cve_number", help="CVE number (e.g., CVE-2023-1234)")
    args = parser.parse_args()

    cve_number = args.cve_number

    copyright_terminal_statement = (
        "CVE Data Fetcher  Copyright (C) 2023  https://github.com/jvossler\n"
        "This program comes with ABSOLUTELY NO WARRANTY.\n"
        "This is free software, and you are welcome to redistribute it\n"
        "under certain conditions; for more details see:\n"
        "License: GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007\n"
        "<https://www.gnu.org/licenses/gpl.html>."
    )
    print(copyright_terminal_statement)

    headers = {"User-Agent": "Mozilla/5.0"}

    # CISA KEV URLs
    # cisa_kev_json_schema = (
    #     "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json"
    # )
    # cisa_kev_csv_dataset = (
    #     "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"
    # )
    cisa_kev_json_dataset = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # MITRE CVE Repository URLs
    # mitre_cve_single_search_url = (
    #     f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={cve_number}"
    # )
    # mitre_cve_github_repository_base_blob_url = (
    #     "https://github.com/CVEProject/cvelistV5/blob/main"
    # )
    # mitre_cve_github_repository_base_tree_url = (
    #     "https://github.com/CVEProject/cvelistV5/tree/main"
    # )
    mitre_cve_github_repository_base_url = (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
    )

    # NIST base URLs for the CVE and CVE Change History APIs
    nist_nvd_cve_url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}"
    )
    nist_nvd_cve_history_url = (
        f"https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={cve_number}"
    )

    # # Additional Resources URLs
    # nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_number}"
    # cve_url = f"https://www.cve.org/CVERecord?id={cve_number}"
    # # virustotal_url = f"https://www.cvedetails.com/cve/{cve_number}"
    # cvedetails_url = f"https://www.cvedetails.com/cve/{cve_number}"

    # additional_resource_urls_dictionary = {
    #     "nvd_url": nvd_url,
    #     "cve_url": cve_url,
    #     "nist_nvd_cve_url": nist_nvd_cve_url,
    #     "nist_nvd_cve_history_url": nist_nvd_cve_history_url,
    #     "cvedetails_url": cvedetails_url,
    #     "google_cve_search": f"https://www.google.com/search?q={cve_number}&ie=UTF-8",
    #     "cisa_cve_search": f"https://www.cisa.gov/search?g={cve_number}",
    # }

    additional_resource_urls_dictionary = {
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_number}",
        "cve_url": f"https://www.cve.org/CVERecord?id={cve_number}",
        "cvedetails_url": f"https://www.cvedetails.com/cve/{cve_number}",
        "nist_nvd_cve_url": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_number}",
        "nist_nvd_cve_history_url": f"https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={cve_number}",
        "google_cve_search": f"https://www.google.com/search?q={cve_number}&ie=UTF-8",
        "cisa_cve_search": f"https://www.cisa.gov/search?g={cve_number}",
    }

    print(f"\n\nAdditional Resource URLs for CVE #: {cve_number}: \n")
    for key, value in additional_resource_urls_dictionary.items():
        try:
            response = requests.get(
                value, headers=headers, timeout=10
            )  # timeout set to 10 seconds
            if response.status_code == 200:
                print(f"{key}: {value}")
            elif response.status_code == 403:
                continue  # Skip to the next URL if the status code is not 200
            else:
                continue  # Skip to the next URL if the status code is not 200
        except requests.exceptions.Timeout:
            continue  # Skip to the next URL if a timeout occurs
        except requests.exceptions.RequestException:
            continue  # Skip to the next URL if any other exception occurs

    # Current date and time in the format YYYYMMDDTHHMM
    # current_datetime = datetime.now().strftime("%Y%m%dT%H%M")
    current_date = datetime.now().strftime("%Y%m%d")

    # Directory for saving results
    results_dir = f"cve_api_results_{current_date}_{cve_number}"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)

    # Retrieve NIST CVE data and write to separate files
    nist_cve_data, nist_cve_history_data = get_nist_cve_info(
        cve_number, nist_nvd_cve_url, nist_nvd_cve_history_url, results_dir, headers
    )
    if nist_cve_data:
        write_to_file(
            nist_cve_data, f"{results_dir}/nist_nvd_cve_data_{cve_number}.json"
        )
    if nist_cve_history_data:
        write_to_file(
            nist_cve_history_data,
            f"{results_dir}/nist_nvd_cve_history_data_{cve_number}.json",
        )

    # Retrieve CISA KEV catalog and write to separate files
    cisa_kev_catalog_filepath = os.path.join(
        results_dir, f"cisa_kev_catalog - as of {current_date}.json"
    )
    cisa_kev_data = download_data(cisa_kev_json_dataset, cisa_kev_catalog_filepath, headers)
    if cisa_kev_data:
        write_to_file(cisa_kev_data, cisa_kev_catalog_filepath)

    # Retrieve CISA KEV CVE data and write to separate files
    cisa_kev_cve_filepath = os.path.join(
        results_dir, f"cisa_kev_data_{cve_number}.json"
    )
    cisa_kev_cve_data = get_cisa_kev_data(
        cve_number, cisa_kev_json_dataset, cisa_kev_cve_filepath, headers
    )
    if cisa_kev_cve_data:
        write_to_file(cisa_kev_cve_data, cisa_kev_cve_filepath)

    # Retrieve MITRE CVE data and write to separate files
    mitre_github_cve_data = get_cve_file_from_github(
        cve_number, mitre_cve_github_repository_base_url
    )
    if mitre_github_cve_data:
        write_to_file(
            mitre_github_cve_data,
            f"{results_dir}/mitre_github_cve_data_{cve_number}.json",
        )


def download_data(url, filepath, headers=None):
    """
    Downloads data from a specified URL and saves it to a file.
    Only downloads if the content has changed based on the hash comparison.

    Args:
        url (str): The URL from which to download data.
        filepath (str): The file path where the data should be saved.

    Returns:
        bool: True if the data was downloaded and saved, False otherwise.
    """

    # headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.content.decode("utf-8")  # Decode the data from UTF-8
        new_data = data
        new_hash = generate_file_hash(new_data)

        # Check if file exists and compare hashes
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as file:
                existing_data = file.read()
            existing_hash = generate_file_hash(existing_data)

            if new_hash == existing_hash:
                print(f"No changes detected for {url}. Skipping download.")
                return False

        # Save the new data to file
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(new_data)
        # print(f"Downloaded and saved data from {url}.")
        return json.loads(new_data)

    except requests.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return False


def write_to_file(data, filepath):
    """
    Writes the provided data to a file in JSON format.

    Args:
        data (dict): The data to be written to the file.
        filepath (str): The file path where the data should be saved.

    Returns:
        None
    """

    try:
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
    except IOError as e:
        print(f"Error writing to file {filepath}: {e}")


def get_nist_cve_info(cve_id, nist_cve_url, nist_cve_history_url, results_dir="", headers=None):
    """
    Retrieves information and change history for a specified CVE ID from the NIST database.

    Args:
        cve_id (str): The CVE ID for which to retrieve information (e.g., 'CVE-2023-1234').
        nist_cve_url (str): URL to the NIST CVE database.
        nist_cve_history_url (str): URL to the NIST CVE history database.
        results_dir (str): Directory where the results are saved.

    Returns:
        tuple: A tuple containing dictionaries for CVE data and change history from NIST.
    """

    nist_cve_filepath = os.path.join(results_dir, f"nist_nvd_cve_data_{cve_id}.json")

    nist_cve_history_filepath = os.path.join(
        results_dir, f"nist_nvd_cve_history_data_{cve_id}.json"
    )

    nist_cve_data = download_data(nist_cve_url, nist_cve_filepath, headers)
    nist_cve_history_data = download_data(
        nist_cve_history_url, nist_cve_history_filepath, headers
    )

    return nist_cve_data, nist_cve_history_data


def get_cisa_kev_data(cve_id, url, results_dir="", headers=None):
    """
    Retrieves data for a specified CVE number from the CISA Known Exploited Vulnerabilities catalog.

    Args:
        cve_id (str): The CVE number for which to retrieve data (e.g., 'CVE-2023-1234').
        url (str): URL to the CISA KEV catalog.
        results_dir (str): Directory where the results are saved.

    Returns:
        dict: A dictionary containing data for the specified CVE from the CISA catalog.
        None: Returns None if the CVE data is not found in the catalog.
    """

    data = download_data(url, results_dir, headers)
    if data:
        for vulnerability in data["vulnerabilities"]:
            if vulnerability["cveID"] == cve_id:  # Corrected the json key here
                return vulnerability
    return None


def get_cve_file_from_github(cve_id, base_url):
    """
    Retrieves a CVE file from the GitHub repository based on the CVE ID.

    Args:
        cve_id (str): The full CVE ID (e.g., 'CVE-2023-4966').
        base_url (str): Base URL to the GitHub repository.

    Returns:
        dict: The content of the CVE file if found, otherwise None.
    """

    year = cve_id.split("-")[1]
    id_segment = cve_id.split("-")[2]
    if len(id_segment) == 4:
        id_segment = id_segment[0] + "xxx"
    elif len(id_segment) == 5:
        id_segment = id_segment[:2] + "xxx"

    file_path = f"/cves/{year}/{id_segment}/{cve_id}.json"
    url = base_url + file_path
    # print(url)

    headers = {"User-Agent": "Mozilla/5.0"}

    response = None
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.content.decode("utf-8")  # Decode the data from UTF-8
        return json.loads(data)
    except requests.RequestException as e:
        print(f"Error fetching data for {cve_id} from {url}: {e}")
        if response is not None:
            print(f"Error fetching data for {cve_id} from {url}: {e}")
        if response:
            print(f"HTTP Status Code: {response.status_code}")
        return None


def generate_file_hash(file_content):
    """
    Generates the SHA256 hash of the given file content.

    Args:
        file_content (str): The content of the file.

    Returns:
        str: The SHA256 hash of the file content.
    """

    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_content.encode("utf-8"))
    # print(sha256_hash.hexdigest())
    return sha256_hash.hexdigest()

def install_and_import_modules(modules):
    """
    Install and import modules.

    Installs the specified Python modules using pip if they are not already
    installed, and then imports them.

    Args:
        modules (list): A list of module names (str) to install and import.

    Returns:
        dict: A dictionary where keys are module names (str) and values
        are the imported modules.
    """

    modules_dict = {}
    for module in modules:
        try:
            imported_module = importlib.import_module(module)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])
            imported_module = importlib.import_module(module)
        modules_dict[module] = imported_module
    return modules_dict


# First, we need to import the modules we need to use in this script
modules = ["argparse", "requests", "nvdlib", "hashlib"]
imported_modules = install_and_import_modules(modules)

# Now we can use the imported modules as usual
argparse = imported_modules["argparse"]
requests = imported_modules["requests"]
# NVDlib Documentation: https://nvdlib.com/en/latest/v2/CVEv2.html
nvdlib = imported_modules["nvdlib"]
hashlib = imported_modules["hashlib"]


if __name__ == "__main__":
    missing_modules = [m for m in modules if m not in sys.modules]
    if missing_modules:
        sys.exit(
            f"Missing required modules: {', '.join(missing_modules)}.\n"
            "Please install them with pip before running this script."
        )

    main()
