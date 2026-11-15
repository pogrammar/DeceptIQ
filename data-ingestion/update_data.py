
import csv
import json
import os
import time
from pathlib import Path
from datetime import datetime, timezone

import requests


# --------------------------------------------------
# 1. Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data" / "NVD_CISA"

ASSETS_FILE = BASE_DIR / "assets.csv"

CVE_FILE = DATA_DIR / "NVD_CVE.json"
CPE_FILE = DATA_DIR / "NVD_CPE.json"
CPEM_FILE = DATA_DIR / "NVD_CPEM.json"
CISA_FILE = DATA_DIR / "CISA.json"
SYNC_FILE = DATA_DIR / "LAST_SYNC.json"

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0/"
CPEM_API = "https://services.nvd.nist.gov/rest/json/cpematch/2.0/"
CISA_API = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

API_KEY = os.getenv("NVD_API_KEY")

# NVD unauthenticated requests are rate-limited.
REQUEST_DELAY = 0.7 if API_KEY else 6.0

PAGE_SIZE_CVE = 2000
PAGE_SIZE_CPE = 10000
PAGE_SIZE_CPEM = 500

session = requests.Session()
session.headers.update({"User-Agent": "DeceptIQ/1.0"})

if API_KEY:
    session.headers.update({"apiKey": API_KEY})


# --------------------------------------------------
# 2. Common utility functions
# --------------------------------------------------

def save_json(file_path, data):
    """Save JSON safely without leaving a partial file."""

    temp_file = file_path.with_suffix(".tmp")

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)

    temp_file.replace(file_path)


def load_json(file_path):
    """Load an existing JSON file."""

    if not file_path.exists():
        return {}

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)



def api_get(url, params=None):
    """Make an API request with extended retry handling."""

    max_attempts = 8

    for attempt in range(max_attempts):
        try:
            time.sleep(REQUEST_DELAY)

            response = session.get(
                url,
                params=params,
                timeout=(20, 180)
            )

            if response.status_code == 200:
                return response.json()

            if response.status_code in (429, 500, 502, 503, 504):
                wait_time = min(30 * (2 ** attempt), 300)

                print(
                    f"NVD returned {response.status_code}. "
                    f"Waiting {wait_time} seconds before retry "
                    f"({attempt + 1}/{max_attempts})..."
                )

                time.sleep(wait_time)
                continue

            response.raise_for_status()

        except requests.RequestException as error:
            wait_time = min(30 * (2 ** attempt), 300)

            print(f"Request error: {error}")

            if attempt == max_attempts - 1:
                raise

            print(f"Retrying in {wait_time} seconds...")
            time.sleep(wait_time)

    raise RuntimeError(f"Unable to retrieve data from {url}")



def fetch_all_pages(url, params, result_key, page_size):
    """Fetch all pages returned by an NVD API endpoint."""

    all_records = []
    start_index = 0

    while True:
        request_params = params.copy()
        request_params["startIndex"] = start_index
        request_params["resultsPerPage"] = page_size

        response = api_get(url, request_params)

        records = response.get(result_key, [])
        all_records.extend(records)

        total_results = response.get("totalResults", len(records))

        print(
            f"Retrieved {len(all_records)} / {total_results} "
            f"{result_key}"
        )

        if not records or len(all_records) >= total_results:
            break

        start_index += len(records)

    return all_records


# --------------------------------------------------
# 3. Read software inventory
# --------------------------------------------------

def get_asset_software():
    """Get unique software names from assets.csv."""

    software_names = set()

    with open("data-ingestion/data/assets.csv", "r", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        for row in reader:
            software = row.get("software", "").strip()

            if software:
                software_names.add(software)

    return sorted(software_names, key=str.lower)


# --------------------------------------------------
# 4. Retrieve relevant CVE records
# --------------------------------------------------


def fetch_cves(software_names):
    """Search NVD and save results after each software search."""

    all_cves = {}

    for software in software_names:

        print(f"\nSearching CVEs for: {software}")

        records = fetch_all_pages(
            CVE_API,
            {
                "keywordSearch": software,
                "noRejected": ""
            },
            "vulnerabilities",
            PAGE_SIZE_CVE
        )

        for record in records:
            cve = record.get("cve", {})
            cve_id = cve.get("id")

            if cve_id:
                all_cves[cve_id] = record

        # Save successful results immediately
        cve_data = {
            "resultsPerPage": len(all_cves),
            "startIndex": 0,
            "totalResults": len(all_cves),
            "vulnerabilities": list(all_cves.values())
        }

        save_json(CVE_FILE, cve_data)

        print(
            f"Saved {len(all_cves)} unique CVEs "
            f"after processing {software}."
        )

    return list(all_cves.values())



# --------------------------------------------------
# 5. Extract CPE Match Criteria IDs from CVEs
# --------------------------------------------------

def extract_match_ids(cve_records):
    """Extract matchCriteriaId values from CVE configurations."""

    match_ids = set()

    def inspect_node(node):
        for match in node.get("cpeMatch", []):
            match_id = match.get("matchCriteriaId")

            if match_id:
                match_ids.add(match_id)

        for child in node.get("nodes", []):
            inspect_node(child)

    def inspect_configuration(configuration):
        for node in configuration.get("nodes", []):
            inspect_node(node)

    for record in cve_records:
        cve = record.get("cve", {})

        for configuration in cve.get("configurations", []):
            inspect_configuration(configuration)

    return sorted(match_ids)


# --------------------------------------------------
# 6. Retrieve relevant CPE Match records
# --------------------------------------------------

def fetch_cpem(match_ids):
    """Retrieve CPE Match records using their UUIDs."""

    all_records = {}

    for match_id in match_ids:
        print(f"Retrieving CPE Match: {match_id}")

        records = fetch_all_pages(
            CPEM_API,
            {"matchCriteriaId": match_id},
            "matchStrings",
            PAGE_SIZE_CPEM
        )

        for record in records:
            match_string = record.get("matchString", {})
            record_id = match_string.get("matchCriteriaId")

            if record_id:
                all_records[record_id] = record

    return list(all_records.values())


# --------------------------------------------------
# 7. Retrieve relevant CPE records
# --------------------------------------------------

def fetch_cpes(match_ids):
    """Retrieve CPE dictionary entries linked to match criteria."""

    all_records = {}

    for match_id in match_ids:
        print(f"Retrieving CPE records: {match_id}")

        records = fetch_all_pages(
            CPE_API,
            {"matchCriteriaId": match_id},
            "products",
            PAGE_SIZE_CPE
        )

        for record in records:
            cpe = record.get("cpe", {})
            record_id = cpe.get("cpeNameId")

            if record_id:
                all_records[record_id] = record

    return list(all_records.values())


# --------------------------------------------------
# 8. Retrieve relevant CISA KEV records
# --------------------------------------------------

def fetch_cisa(cve_records):
    """Download CISA KEV and retain CVEs found in our dataset."""

    print("\nDownloading CISA KEV catalogue...")

    response = api_get(CISA_API)

    cve_ids = {
        record.get("cve", {}).get("id")
        for record in cve_records
    }

    relevant_entries = [
        entry
        for entry in response.get("vulnerabilities", [])
        if entry.get("cveID") in cve_ids
    ]

    return {
        **response,
        "count": len(relevant_entries),
        "vulnerabilities": relevant_entries
    }


# --------------------------------------------------
# 9. Main update process
# --------------------------------------------------

def main():

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("======================================")
    print("       DeceptIQ Data Updater")
    print("======================================")

    # Read installed software
    software_names = get_asset_software()

    print("\nSoftware found in assets.csv:")
    for software in software_names:
        print(f"- {software}")

    if not software_names:
        raise ValueError("No software found in assets.csv")

    # Retrieve CVE records
    cve_records = fetch_cves(software_names)

    if not cve_records:
        raise RuntimeError(
            "No CVE records retrieved. Existing files were not replaced."
        )

    # Extract CPE Match UUIDs
    match_ids = extract_match_ids(cve_records)

    print(f"\nUnique CPE Match IDs: {len(match_ids)}")

    # Retrieve CPE Match records
    cpem_records = fetch_cpem(match_ids)

    # Retrieve CPE records
    cpe_records = fetch_cpes(match_ids)

    # Retrieve relevant CISA records
    cisa_data = fetch_cisa(cve_records)

    # Prepare NVD-style JSON structures
    cve_data = {
        "resultsPerPage": len(cve_records),
        "startIndex": 0,
        "totalResults": len(cve_records),
        "vulnerabilities": cve_records
    }

    cpem_data = {
        "resultsPerPage": len(cpem_records),
        "startIndex": 0,
        "totalResults": len(cpem_records),
        "matchStrings": cpem_records
    }

    cpe_data = {
        "resultsPerPage": len(cpe_records),
        "startIndex": 0,
        "totalResults": len(cpe_records),
        "products": cpe_records
    }

    # Save all four datasets
    save_json(CVE_FILE, cve_data)
    save_json(CPE_FILE, cpe_data)
    save_json(CPEM_FILE, cpem_data)
    save_json(CISA_FILE, cisa_data)

    # Update synchronization information
    sync_data = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "software": software_names,
        "nvd_cve": len(cve_records),
        "nvd_cpe": len(cpe_records),
        "nvd_cpem": len(cpem_records),
        "cisa": len(cisa_data.get("vulnerabilities", []))
    }

    save_json(SYNC_FILE, sync_data)

    print("\n======================================")
    print("       DATA UPDATE COMPLETED")
    print("======================================")
    print(f"CVE records       : {len(cve_records)}")
    print(f"CPE records       : {len(cpe_records)}")
    print(f"CPE Match records : {len(cpem_records)}")
    print(
        "CISA KEV records  : "
        f"{len(cisa_data.get('vulnerabilities', []))}"
    )
    print("\nAll four source files have been updated.")


if __name__ == "__main__":
    main()
