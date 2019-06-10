import re
import subprocess

from fame.core.module import ProcessingModule


class YaraPdfFilter(ProcessingModule):
    name = "yara_pdf_filter"
    description = "Look for Yara patterns inside unfiltered PDF streams."

    config = [
        {
            'name': 'pdf_parser_path',
            'type': 'str',
            'description': 'pdf-parser.py full script path.'
        },
        {
            'name': 'yara_rules',
            'type': 'str',
            'description': 'Yara rules path. (NOT COMPILED)'
        },
    ]

    def each(self, target):

        match_found = False
        
        args = [self.pdf_parser_path, "-y", self.yara_rules, target]

        scan_proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = scan_proc.communicate()

        if scan_proc.returncode != 0:
            self.log("error", "There was an error executing pdf-parser: {}".format(stderr))

        lines = stdout.strip().split('\n')

        # Look for matches e.g.: "YARA rule: matched_rule_name (/path/to/rule.yar)"
        patt = r"YARA rule: (\w+) \("
        
        for line in lines:
            if not line.startswith("YARA rule"):
                continue

            match_found = True

            matches = re.findall(patt, line)
            if matches:
                rule = matches[0]
                self.add_tag(rule)

        return match_found
