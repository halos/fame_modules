import os
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
        version_str = ".".join(version_str.split(".", 2)[:2])
        version_float = float(version_str)

        return version_float

    def each(self, target):
        
        yara_version = self.get_yara_version()

        if yara_version >= 3.9:
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

        lines = stdout.strip().split('\n')

        for line in lines:
            rule = line.split()[0]
            self.add_tag(rule)

        return True
