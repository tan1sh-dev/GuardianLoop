# Intentionally vulnerable sample: CWE-611 XML External Entity (XXE).
#
# xml.etree.ElementTree.parse() does not disable external entity resolution.
# An attacker who controls the XML input can read local files or probe
# internal network services.
#
# A correct patch must use defusedxml:
#   import defusedxml.ElementTree as ET
#   tree = ET.parse(xml_file)

import xml.etree.ElementTree as ET
import sys


def parse_user_xml(xml_file):
    # VULNERABLE: standard library XML parser does not disable external entities.
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for child in root:
        print(f"Tag: {child.tag}, Text: {child.text}")
    return root


def parse_xml_string(xml_string):
    # VULNERABLE: fromstring also processes external entities.
    root = ET.fromstring(xml_string)
    return root


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python demo_cwe611.py <xml_file>")
        sys.exit(1)
    parse_user_xml(sys.argv[1])
