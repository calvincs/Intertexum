"""Expose pytest failures as GitHub annotations, including on public checks APIs."""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def report(path):
    if not Path(path).is_file():
        print('::error::Pytest did not produce its JUnit report; inspect the test runner log.')
        return
    root = ET.parse(path).getroot()
    for case in root.iter('testcase'):
        for failure in list(case.findall('failure')) + list(case.findall('error')):
            detail = case.get('classname', '') + '::' + case.get('name', '')
            detail += '\n' + (failure.text or failure.get('message', 'Test failed'))[-6000:]
            escaped = detail.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::error::' + escaped)


if __name__ == '__main__':
    report(sys.argv[1])
