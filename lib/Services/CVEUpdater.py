from requests.auth import HTTPBasicAuth
from datetime import datetime
import time
import requests
import json
import os
from os.path import exists
import re
from packaging.version import Version
from dotenv import load_dotenv

load_dotenv()

class CVEUpdater():
    def __init__(self, versions):
        self.versions = versions
        self.api_key = os.getenv('NIST_API_KEY', '')
    
    def GetVulnerabilities(self):
        cached_cves_f = [pos_json for pos_json in os.listdir('.') if pos_json.startswith('CachedCVEs')]
        if cached_cves_f:
            if exists(cached_cves_f[0]):
                if not os.stat(cached_cves_f[0]).st_size == 0:
                    print("Cached file found")
                    cached_vulnerabilities = self.get_CVEs_Local(cached_cves_f[0])
                    new_vulnerabilities = {}

                    # Check if there is a new service that doesn't exist in the cached file
                    for service, version in self.versions.items():
                        if  not version == "Unknown" and not service in cached_vulnerabilities.keys():
                            new_vulnerabilities = self.get_CVEs_NIST({service:version})

                    all_vulnerabilities =  cached_vulnerabilities | new_vulnerabilities
                    self.writeTofile(all_vulnerabilities, False, cached_cves_f[0])
                    return all_vulnerabilities
        else:
            vulnerabilities = self.get_CVEs_NIST()
            self.writeTofile(vulnerabilities)

        return vulnerabilities

    def get_CVEs_Local(self, cached_cves_f):
        pattern = r"(\d.*?).json"
        match = re.search(pattern, cached_cves_f)
        date_str = match.group(1)
        current_dtime = datetime.today().strftime('%Y_%m_%d')
        current_dtime = datetime.strptime(current_dtime, "%Y_%m_%d")
        file_date = datetime.strptime(date_str, "%Y_%m_%d")
        
        
        delta = current_dtime - file_date
        if delta.days < 7:
            with open(cached_cves_f, "r") as f:
                loaded_json = json.load(f)    
            return loaded_json
        else:
            print("Cache file is outdated.")
            print("Retrieving new data... Please wait ")
            os.remove(cached_cves_f)
            vulnerabilities = self.get_CVEs_NIST()
            self.writeTofile(vulnerabilities)
            return vulnerabilities

    def get_CVEs_NIST(self, versions={}):
        vulnerabilities = {}
        auth = HTTPBasicAuth("apiKey", self.api_key)
        headers = {"Accept": "application/json"}
        if not versions:
            versions = self.versions
        
        for service in versions:
            resultsPerPage = 0
            if not self.versions[service] == "Unknown":
                print(f"Searching CVEs for service {service}")
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
                response = requests.get(url, headers=headers, auth=auth)

                while not response.status_code == 200:
                    time.sleep(6)
                    response = requests.get(url, headers=headers, auth=auth)
                data = json.loads(response.text)
                while data["totalResults"] > data["resultsPerPage"]:
                    resultsPerPage += data["resultsPerPage"]
                    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex={resultsPerPage}&keywordSearch={service}"
                    response = requests.get(url, headers=headers, auth=auth)
                    data = json.loads(response.text)
                vulnerabilities[service] = data
                time.sleep(6)
            
        return vulnerabilities
        
    
    
    def writeTofile(self, data, update_date=True, f_name="cachedFile"):
        if update_date:
            dtime = datetime.today().strftime('%Y_%m_%d')
            with open(f"CachedCVEs{dtime}.json", "w+") as f:
                json.dump(data, f)
        else:
            with open(f_name, "w") as f:
                json.dump(data, f)

    def CVEfilter(self, vulnerabilities):
        active_vulnerbilities = {}
        possible_vulnerabilities = {}
        for service_name, service_version in self.versions.items():
            
            try:
                if not vulnerabilities[service_name]['resultsPerPage'] > 0:
                    continue
            except:
                # if services doesn't exist in the vulnerabilities dict
                continue
            cve_counter = 0
            cves = vulnerabilities[service_name]['vulnerabilities']
            while cve_counter <= len(cves):
                cve_counter +=1
                # Check if NIST has returned any vulnerabilities for each services   
                if not service_version == "Unknown":
                    pattern = r"^([\d.-]+)"
                    if cves:
                        active_cve_IDs = []
                        possible_cve_IDs = []
                        for cve in cves:
                            starting_version = "0"
                            ending_version = "0"
                            starting_version_match = ""
                            has_startingVersionIncluding = False
                            has_endingVersionIncluding = False
                            has_startingVersionExcluding = False
                            has_endingVersionExcluding = False
                            
                            try:
                                for cpeIndex in range(len(cve['cve']['configurations'][0]["nodes"][0]["cpeMatch"])):
                                    if not has_startingVersionIncluding:
                                        try:
                                            starting_version_including = cve['cve']['configurations'][0]["nodes"][0]["cpeMatch"][cpeIndex]["versionStartIncluding"]
                                            starting_version_match = re.search(pattern, starting_version_including)
                                            has_startingVersionIncluding = True
                                        except:
                                            pass
                                    
                                    if not has_startingVersionExcluding:
                                        try:
                                            starting_version_excluding = cve['cve']['configurations'][0]["nodes"][0]["cpeMatch"][cpeIndex]["versionStartExcluding"]
                                            starting_version_match = re.search(pattern, starting_version_excluding)
                                            has_startingVersionExcluding = True
                                        except:
                                            pass

                                    if starting_version_match:
                                        starting_version = starting_version_match.group(0)
                                    
                                    try:
                                        ending_version_including = cve['cve']['configurations'][0]["nodes"][0]["cpeMatch"][cpeIndex]["versionEndIncluding"]
                                        ending_version_match = re.search(pattern, ending_version_including)
                                        has_endingVersionIncluding = True
                                    except:
                                        pass
                                    
                                    try:
                                        ending_version_excluding = cve['cve']['configurations'][0]["nodes"][0]["cpeMatch"][cpeIndex]["versionEndExcluding"]
                                        ending_version_match = re.search(pattern, ending_version_excluding)
                                        has_endingVersionExcluding = True
                                    except:
                                        pass
                                    
                                    if ending_version_match:
                                        ending_version = ending_version_match.group(0)

                            except:
                                pass

                            try:
                                Version(service_version)
                            except:
                                service_version = "0"

                            try:
                                Version(starting_version)
                            except:
                                starting_version = "0"

                            try:
                                Version(ending_version)
                            except:
                                ending_version = "0"


                            service_version_match = re.search(pattern, service_version)
                            if service_version_match:
                                service_version = service_version_match.group(0)
                                if service_version != "0":
                                    if ((has_startingVersionIncluding and Version(service_version) >= Version(starting_version)) or (has_startingVersionExcluding and Version(service_version) > Version(starting_version))) and \
                                        ((has_endingVersionIncluding and Version(service_version) <= Version(ending_version)) or (has_endingVersionExcluding and Version(service_version) < Version(ending_version))):
                                        if service_name not in active_vulnerbilities:
                                            active_vulnerbilities[service_name] = {}
                                        
                                        try:
                                            cve_ID = {"CVE": cve['cve']['id'],
                                                        "Severity": cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
                                                        "Exploitability Score": cve['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'],
                                                        "Impact Score": cve['cve']['metrics']['cvssMetricV2'][0]['impactScore'],
                                                        "Service Version": service_version,
                                                        "Starting Version": starting_version,
                                                        "Ending Version": ending_version}
                                        except:
                                            cve_ID = {"CVE": cve['cve']['id'],
                                                        "Severity": cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],
                                                        "Exploitability Score": cve['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore'],
                                                        "Impact Score": cve['cve']['metrics']['cvssMetricV31'][0]['impactScore'],
                                                        "Service Version": service_version,
                                                        "Starting Version": starting_version,
                                                        "Ending Version": ending_version}

                                        active_cve_IDs.append(cve_ID)
                                    elif ((not (has_startingVersionIncluding or has_startingVersionExcluding)) and (((has_endingVersionIncluding and Version(service_version) <= Version(ending_version)) or (has_endingVersionExcluding and Version(service_version) < Version(ending_version))))) or \
                                        ((not (has_endingVersionIncluding or has_endingVersionExcluding)) and (((has_startingVersionIncluding and Version(service_version) >= Version(starting_version)) or (has_startingVersionExcluding and Version(service_version) > Version(starting_version))))):
                                        if service_name not in possible_vulnerabilities:
                                                possible_vulnerabilities[service_name] = {}

                                        try:
                                            cve_ID = {"CVE": cve['cve']['id'],
                                                        "Severity": cve['cve']['metrics']['cvssMetricV2'][0]['baseSeverity'],
                                                        "Exploitability Score": cve['cve']['metrics']['cvssMetricV2'][0]['exploitabilityScore'],
                                                        "Impact Score": cve['cve']['metrics']['cvssMetricV2'][0]['impactScore'],
                                                        "Service Version": service_version,
                                                        "Starting Version": starting_version,
                                                        "Ending Version": ending_version}
                                        except:
                                            cve_ID = {"CVE": cve['cve']['id'],
                                                        "Severity": cve['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],
                                                        "Exploitability Score": cve['cve']['metrics']['cvssMetricV31'][0]['exploitabilityScore'],
                                                        "Impact Score": cve['cve']['metrics']['cvssMetricV31'][0]['impactScore'],
                                                        "Service Version": service_version,
                                                        "Starting Version": starting_version,
                                                        "Ending Version": ending_version}
                                        possible_cve_IDs.append(cve_ID)
                                else:
                                    break
                    else:
                        break
                else:
                    break
            if service_name in active_vulnerbilities:
                active_vulnerbilities[service_name] = active_cve_IDs
            
            if service_name in possible_vulnerabilities:
                possible_vulnerabilities[service_name] = possible_cve_IDs


        return active_vulnerbilities, possible_vulnerabilities
