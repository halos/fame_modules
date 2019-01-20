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


    def each(self, target):
        
        scan_proc = subprocess.Popen(
            [self.bin_path, self.compiled_rules, target], stdout=subprocess.PIPE)
        output = scan_proc.communicate()[0]

        if len(output) == 0:
            return False

        lines = output.strip().split('\n')

        for line in lines:
            rule = line.split()[0]
            self.add_tag(rule)

        return True
