import os
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from distutils.spawn import find_executable


try:
    import pcodedmp
    HAVE_PCODEDMP = True
except ImportError:
    HAVE_PCODEDMP = False

if find_executable("sigtool") is not None:
    HAVE_SIGTOOL = True
else:
    HAVE_SIGTOOL = False


class VbaStomp(ProcessingModule):
    name = "vba_stomp"
    description = "Detects anomalies inside documents with VBA code."
    acts_on = ["word", "html", "excel", "powerpoint"]

    config = [
        {
            'name': 'pcodedmp_dir',
            'type': 'str',
            'description': 'pcodedmp.py folder path.'
        },
        {
            'name': 'vba_seismograph_path',
            'type': 'str',
            'description': 'vba_seismograph.py file path.'
        },
    ]

    def initialize(self):
        if not HAVE_PCODEDMP:
            raise ModuleInitializationError(self, "Missing dependency: pcodedmp")

        if not HAVE_SIGTOOL:
            raise ModuleInitializationError(self, "Missing dependency: sigtool")

    def each(self, target):

        self.results = {
            'exit_code': 0,
            'output': u''
        }

        scan_proc = subprocess.Popen(
            ["python", self.vba_seismograph_path, target],
            stdout=subprocess.PIPE,
            env=dict(os.environ, PCODEDMP_DIR=self.pcodedmp_dir)
        )
        if scan_proc.returncode == 0:
            return False

        self.results["exit_code"] = scan_proc.returncode
        self.results["output"] = scan_proc.communicate()

        return True
