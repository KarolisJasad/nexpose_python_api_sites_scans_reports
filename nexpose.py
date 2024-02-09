import time
import os
import string
import random
import argparse
import urllib3
import requests
from requests.auth import HTTPBasicAuth
from config_example import configs

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class NexposeSession:
    """
    Initiates Nexposes API
    """
    def __init__(self, api_url, username, password):
        """
        Makes a connection to Nexpose API
        
        Args:\n
        api_url = the url of the nexpose api. Ex:
        https://localhost:3780/api/3 \n
        username = the username of the nexpose user
        with the right privileges to the API.\n
        password = password of the user.        
        """
        self.api_url = api_url
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = False

class Site(NexposeSession):
    """
    Class responsible for Site configurations/creations
    """
    def get_site_id(self, name):
        """
        Gets the ID of a specific site
        
        Args:\n
        name = the name of the site we want the id of.

        Takes name as an input to check if such a site exists.
        If it exists, gets its ID otherwise returns None.
        """
        scan_url = f'{self.api_url}/sites'
        response = self.session.get(scan_url) 
        if response.status_code in [200, 201, 202]:
            try:
                response_json = response.json()
                for site in response_json.get("resources", []):
                    if site.get("name") == name:
                        return site.get("id")
            except ValueError:
                print("Failed to parse JSON response from the server.")
        return None

    def create_site(self, name, description, target_ip, template_id):
        """
        Creates a site based on given inputs.
        Checks if such a site exists.
        
        Args:\n
        name = the name of the site.\n
        description = description of the site.\n
        target_ip = ip we want to scan.\n
        template_id = the id of the scan template.
            https://localhost:3780/api/3/scan_templates
            gives a list of template ids.\n
        
        If site doesn't exist, creates a new site based
        on given parameters, otherwise returns site_id.
        """
        site_id = self.get_site_id(name)
        if site_id is not None:
            print(f"Site already exists, using existing site id: {site_id}")
            return
        sites_url = f'{self.api_url}/sites'
        site_data = {
            "name": name,
            "description": description,
            "scan": {
                "assets": {
                    "includedTargets": {
                        "addresses": [target_ip],
                    }
                }
            },
            "scanTemplateId": template_id
        }
        response = self.session.post(sites_url, json=site_data)
        if response.status_code in [200, 201, 202]:
            print("Site created successfully")
        else:
            print("Failed to create site")

class Scan(NexposeSession):
    """
    Class responsible for starting a scan.
    """
    def start_scan(self, site_id):
        """
        Starts a scan on a given site.
        
        Args:\n
        site_id = the ID of a site we wish to scan.
        
        If scan is started returns the scan id
        of the last scan started so we can check
        if the scan is finished. Otherwise returns
        None
        """
        scan_url = f'{self.api_url}/sites/{site_id}/scans'
        response = self.session.post(scan_url)
        if response.status_code in [200, 201, 202]:
            print("Scan started successfully")
            return self.get_last_scan_id()
        print("Scan didnt start")
        return None

    def get_last_scan_id(self):
        """
        Gets the scan id of the last started scan.
        
        Function is required to get the scan id
        of the last scan started which is associated
        to the scan we just started.\n
        
        The scan ids are found in response_last_page.
        If we have a lot of scans response_last_page
        returns a lot of pages so we need to get to
        the last page.
        last_page_url = next((link["href"] for link in links if link["rel"] == "last"), None)
        
        Returns last scan id if its found, otherwise
        None        
        """
        scans_url = f'{self.api_url}/scans'
        status_codes = [200, 201, 202]
        response = self.session.get(scans_url)

        if response.status_code in status_codes:
            try:
                scan_json = response.json()
                links = scan_json.get("links", [])
                last_page_url = next((link["href"] for link in links if link["rel"] == "last"), None)
                if last_page_url is not None:
                    response_last_page = self.session.get(last_page_url)
                else:
                    response_last_page = self.session.get(scans_url)
                if response_last_page.status_code in status_codes:
                    last_page_json = response_last_page.json()
                    resources = last_page_json.get("resources", [])
                    if resources:
                        return resources[-1].get("id")
            except ValueError:
                print("Failed to parse JSON response from the server.")
        return None

    def wait_for_scan_completion(self, scan_id):
        """
        Waits for scan completion.
        
        Args:\n
        scan_id = the id of the scan we wait for completion
        
        Function is needed if we want to fully automate
        scan start and report download. Otherwise
        we can just leave the scan hanging.
        """
        scan_url = f'{self.api_url}/scans/{scan_id}'
        while True:
            response = self.session.get(scan_url)
            if response.status_code in [200, 201, 202]:
                try:
                    scan_json = response.json()
                    status = scan_json.get("status")
                    print(f"{response.status_code} : {status}")
                    if status in ["finished", "stopped"]:
                        print(f"Scan {status} successfully")
                        return
                except ValueError:
                    print("Failed to parse JSON response from the server.")
            else:
                print(response.status_code)
            time.sleep(150)

class ReportGeneration(NexposeSession):
    """Class responsible for Report generation"""
    def create_report(self, site_id, scan_id, name, file_format, template):
        """
        Creates the report based on given inputs if the report doesn't exist.
        Doesn't generate it yet. Just the configs of the report.
        
        Args:\n
        site_id = the ID of the site we want a report\n
        scan_id = the ID of the scan of the site we want a report\n
        name = name of the report\n
        file_format = the format of the report we want\n
        template = the template name of the report we want
        https://localhost:3780/api/3/report_templates\n
        
        After generation or if a report
        already exists returns report_id
        otherwise returns None.
        """
        report_id = self.get_existing_report(site_id)
        if report_id:
            print("Using existing report")
            return report_id
        report_config_url = f'{self.api_url}/reports'
        report_data = {
            "name": f"{name} report - scan ID {scan_id}",
            "format": file_format,
            "scope": {
                "sites": [site_id]
            },
            "template": template,
        }
        response = self.session.post(report_config_url, json=report_data)
        if response.status_code in [200, 201, 202]:
            report_config_json = response.json()
            report_id = report_config_json.get("id")
            print("Report configuration created successfully, report ID:", report_id)
            return report_id
        print("Failed to create report configuration")
        return None

    def get_existing_report(self, site_id):
        """
        Checks if a report already exists.
        
        Args:
        site_id = the ID of the site we want to check
        
        If a report already exists
        Returns the the id of the report
        otherwise returns None
        """
        report_config_url = f'{self.api_url}/reports'
        response = self.session.get(report_config_url)
        if response.status_code in [200, 201, 202]:
            try:
                response_json = response.json()
                for report in response_json.get("resources", []):
                    if site_id in report.get("scope", {}).get("sites", []):
                        return report.get("id")
            except ValueError:
                print("Failed to parse JSON response from the server.")
        return None

    def start_report_generation(self, report_id):
        """
        Starts the generation of the report based on
        previous configurations.
        
        Inputs:\n
        report_id = the id of a report we want to generate.
        """
        generate_report_url = f'{self.api_url}/reports/{report_id}/generate'
        response = self.session.post(generate_report_url)
        if response.status_code in [200, 201, 202]:
            print("Report generation started successfully.")
        else:
            print(f"Failed to start report generation. Status code: {response.status_code}")

    def wait_for_report_completion(self, report_id):
        """
        Waits for the report to finish generating
        
        Args:\n
        report_id = the id of a report that is generating.
        
        Keeps making requests to the latest report
        to check if it's status changed to generated.
        If it is generated returns the timestamp it has finished.
        """
        report_history_url = f'{self.api_url}/reports/{report_id}/history/latest'
        while True:
            response = self.session.get(report_history_url)
            if response.status_code in [200, 201, 202]:
                try:
                    report_json = response.json()
                    status = report_json.get("status")
                    timestamp = report_json.get("generated")
                    if status == "complete":
                        print("Report completed successfully")
                        return timestamp
                except ValueError:
                    print("Failed to parse JSON response from the server.")
            time.sleep(30)

class ReportDownloader(NexposeSession):
    """
    Class responsible for report downloading
    """
    def download_report(self, report_id, instance='latest', directory_name=None, address=None, save_filename='report.pdf'):
        """
        Downloads the report based on inputs

        Args:\n
        report_id = the id of a report we wish to download.\n
        instance = default set to download latest report.\n
        directory_name = name of the folder we want to save in.\n
        address = appends this address to the folder name.\n
        save_filename = the name of the report file. Default report.pdf\n
        
        Creates the folder and downloads the report in it.
        If the folder already exists returns error otherwise
        returns save_path.
        """
        if directory_name is not None and address is not None:
            if not os.path.exists(directory_name):
                os.makedirs(f"{directory_name}_{address}")
            save_path = os.path.join(f"{directory_name}_{address}", save_filename)
        else:
            directory_name = 'reports'
            if not os.path.exists(directory_name):
                os.makedirs(directory_name)
            save_path = os.path.join(f"{directory_name}", save_filename)

        download_url = f'{self.api_url}/reports/{report_id}/history/{instance}/output'

        response = self.session.get(download_url, stream=True)

        if response.status_code == 200:
            with open(save_path, 'wb') as file:
                for content in response.iter_content():
                    file.write(content)
            print(f"Report downloaded and saved to {save_path}")
            return save_path
        print(f"Failed to download report. Status code: {response.status_code}")
        return None

class UtilityFunctions:
    """
    Class responsible for utility functions
    """
    @staticmethod
    def generate_password(length):
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

# Example
if __name__ == "__main__":
    API_URL = configs['nexpose_url']
    USERNAME = configs['nexpose_user']
    PASSWORD = configs['nexpose_password']
    TEMPLATE_ID = configs['template_id']
    REPORT_FORMAT = configs['report_format']
    REPORT_TEMPLATE = configs['report_template']
    SAVE_FILENAME = configs['save_filename']
    DESCRIPTION = "Scan description" # Description of the scan

    parser = argparse.ArgumentParser(description="Run a scan with specified parameters")
    parser.add_argument('-s', '--scan-name', type=str, required=True, help="Name of the scan")
    parser.add_argument('-t', '--target', type=str, required=True, help="IP or Domain of targeted scan")
    args = parser.parse_args()

    SCAN_NAME = args.scan_name.strip().title()
    TARGET_IP = args.target.strip().title()

    # Start Nexpose API session
    session = NexposeSession(API_URL, USERNAME, PASSWORD)
    site = Site(API_URL, USERNAME, PASSWORD)
    scan = Scan(API_URL, USERNAME, PASSWORD)
    report_generation = ReportGeneration(API_URL, USERNAME, PASSWORD)
    report_downloader = ReportDownloader(API_URL, USERNAME, PASSWORD)

    # Create site
    site.create_site(SCAN_NAME, DESCRIPTION, TARGET_IP, TEMPLATE_ID)
    site_id = site.get_site_id(SCAN_NAME)
    print(site_id)

    # Start scan
    scan_id = scan.start_scan(site_id)
    print(scan_id)
    scan.wait_for_scan_completion(scan_id)

    # Generate report
    report_id = report_generation.create_report(site_id, scan_id, SCAN_NAME, REPORT_FORMAT, REPORT_TEMPLATE)
    print(report_id)
    report_generation.start_report_generation(report_id)
    timestamp = report_generation.wait_for_report_completion(report_id)

    # Download report
    report_downloader.download_report(report_id, directory_name=timestamp, address=TARGET_IP, save_filename=SAVE_FILENAME)
