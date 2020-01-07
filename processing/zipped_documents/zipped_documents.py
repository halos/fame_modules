import os
import re
import hexdump
import subprocess
from zipfile import ZipFile

from fame.core.module import ProcessingModule
from fame.common.utils import tempdir

class ZippedDocuments(ProcessingModule):
    name = "zipped_documents"
    description = "Look for Yara patterns inside zipped documents like docx or odt."
    acts_on = "odt,docx"

    config = [
        {
            'name': 'bin_path',
            'type': 'str',
            'default': '/usr/bin/yara',
            'description': 'Yara binary path.'
        },
        {
            'name': 'compiled_rules',
            'type': 'str',
            'description': 'Compiled rules path.'
        },
    ]

    def get_yara_version(self):

        scan_proc = subprocess.Popen(
            [self.bin_path, "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = scan_proc.communicate()

        if scan_proc.returncode != 0:
            self.log("error", "Error getting Yara version: {}".format(stderr))

        version_str = stdout.strip()
        # Split after 2nd dot
        version, sub_version = version_str.split(".", 2)[:2]
        version_int = int(version) * 1000 + int(sub_version)

        return version_int

    def show_hexdump(self, target, output):

        matches = {}
        patt_full_rule = r"(?P<rule>\w+?) (?:.+?)\n(?P<matches>(?:(?:0x[0-9a-fA-F]+?):\$(?:.*?): (?:.*?)(?:\n|$))+)"
        patt_condition = r"(?:(0x.*?):\$(.*?): .*?(?:\n|$))+?"

        for rule_name, conditions in re.findall(patt_full_rule, output):    
            matches[rule_name] = []
            
            for offset_str, condition in re.findall(patt_condition, conditions):
                with open(target, "rb") as fd:
                    offset = int(offset_str, 16)
                    offset = max(offset-32, 0)

                    fd.seek(offset, 0)
                    buff = fd.read(16*5)
                    hex_str = hexdump.hexdump(buff, result="return")
                    matches[rule_name].append((condition, offset_str, hex_str))

        return matches

    def look_for_yaras(self, target):
        
        self.results = {}
        yara_version = self.get_yara_version()

        # version > 3.9
        if yara_version >= 3009:
            args = [self.bin_path, "-s", "-C", self.compiled_rules, target]
        else:
            args = [self.bin_path, "-s", self.compiled_rules, target]

        scan_proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = scan_proc.communicate()

        if scan_proc.returncode != 0:
            self.log("error", "There was an error executing Yara: {}".format(stderr))

        if len(stdout) == 0:
            return False

        matches = self.show_hexdump(target, stdout)
        self.results["matches"] = matches

        for rule in matches.keys():
            self.add_tag(rule)

        return True

    def each(self, target):

        files_to_analyze = []
        tmpdir = tempdir()
        zf = ZipFile(target)

        namelist = zf.namelist()

        for zipped_name in namelist:
            for ext in [".rels", ".xml"]:
                if ext in zipped_name:
                    files_to_analyze.append(zipped_name)
                    break

        for name in files_to_analyze:
            filepath = zf.extract(name, tmpdir)
            if os.path.isfile(filepath):
                self.look_for_yaras(filepath)

        return True
