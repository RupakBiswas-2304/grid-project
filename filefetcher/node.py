import sys
import subprocess
import requests

class NodeClone():
    def __init__(self,url):
        version = "latest"
        if ("==" in url):
            version = url.split("==")[1]
            url = url.split("==")[0]
        elif (":" in url):
            url = url.split(":")[0]
            version = url.split(":")[1]
        
        self.url = url
        self.version = version
        self.info_page_api = f"https://registry.npmjs.org/{url}/{version}"


    def gather_info(self) -> None:
        print("Gathering info ...")

        try:
            response = requests.get(self.info_page_api)
            response.raise_for_status()
            self.info = response.json()
        except Exception as e:
            print(e)
            print("Error: Could not gather info")
            sys.exit()
        
        if self.version == "latest":
            print("Version not mentioned. Downloading latest version")
        self.download_url = self.info['dist']['tarball']
        self.filename = self.info['dist']['tarball'].split("/")[-1]
        self.file_ext = "tgz"

    def download_file(self) -> None:
        print("Downloading file ...")
        try:
            subprocess.call(["rm", "-rf", "tmp"])
            subprocess.call(['mkdir','tmp'])
            subprocess.call(["wget", self.download_url, "-O", "tmp/{}".format(self.filename)])
        except Exception as e:
            print(e)
            print("Error: Could not download file")
            sys.exit()
        print("File Downloaded.")

    def extract_tgz(self):
        print("Extracting file ...")
        try:
            subprocess.call(["tar", "-xzf", "tmp/{}".format(self.filename), "-C", "tmp"])
        except Exception as e:
            print(e)
            print("Error: Could not extract file")
            sys.exit()
        print("File Extracted.")