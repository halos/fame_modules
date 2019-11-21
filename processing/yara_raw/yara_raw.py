import os
import re
import hexdump
import subprocess

from fame.core.module import ProcessingModule


class YaraRaw(ProcessingModule):
    name = "yara_raw"
    description = "Look for Yara patterns inside any type of file."

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

        patt_full_rule = r"(?P<rule>\w+?) (?:.+?)\n(?P<matches>(?:(?:0x[0-9a-fA-F]+?):\$(?:.*?): (?:.*?)(?:\n|$))+)"
        patt_condition = r"(?:(0x.*?):\$(.*?): .*?(?:\n|$))+?"

        for rule_name, conditions in re.findall(patt_full_rule, output):
            self.log("WARNING", "rule: {}".format(rule_name))
            for offset, condition in re.findall(patt_condition, conditions):
                self.log("WARNING", "condition: {} @ {}".format(condition, offset))
                with open(target, "rb") as fd:
                    offset = int(offset, 16)
                    offset = max(offset-32, 0)

                    fd.seek(offset, 0)
                    buff = fd.read(16*5)
                    self.log("WARNING", "hexdump: {}".format(hexdump.hexdump(buff, result="return")))

    def each(self, target):
        
        yara_version = self.get_yara_version()

        # version > 3.9
        if yara_version >= 3009:
            args = [self.bin_path, "-C", self.compiled_rules, target]
        else:
            args = [self.bin_path, self.compiled_rules, target]

        scan_proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = scan_proc.communicate()

        if scan_proc.returncode != 0:
            self.log("error", "There was an error executing Yara: {}".format(stderr))

        if len(stdout) == 0:
            return False

        self.show_hexdump(target, stdout)

        lines = stdout.strip().split('\n')

        for line in lines:
            rule = line.split()[0]
            self.add_tag(rule)

        return True
