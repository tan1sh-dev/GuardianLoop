# Intentionally vulnerable sample: CWE-22 Zip Slip.
#
# tarfile.extractall() and zipfile.extractall() extract archive members
# without validating their paths. A malicious archive can contain entries
# like "../../etc/crontab" that escape the target directory.
#
# A correct patch must iterate over members and validate each path:
#   for member in tar.getmembers():
#       target = Path(dest) / member.name
#       if not target.resolve().is_relative_to(Path(dest).resolve()):
#           raise ValueError(f"Path traversal detected: {member.name}")

import tarfile
import zipfile
import sys


def extract_tar(archive_path, dest_dir):
    # VULNERABLE: extractall without path validation enables Zip Slip.
    tar = tarfile.open(archive_path, "r:gz")
    tar.extractall(dest_dir)
    tar.close()


def extract_zip(archive_path, dest_dir):
    # VULNERABLE: extractall without path validation enables Zip Slip.
    zf = zipfile.ZipFile(archive_path, "r")
    zf.extractall(dest_dir)
    zf.close()


def extract_single_tar(archive_path, member_name, dest_dir):
    # VULNERABLE: single member extract without validation.
    tar = tarfile.open(archive_path, "r:gz")
    tar.extract(member_name, dest_dir)
    tar.close()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python demo_cwe22_zipslip.py <archive> <dest_dir>")
        sys.exit(1)
    archive = sys.argv[1]
    dest = sys.argv[2]
    if archive.endswith(".tar.gz"):
        extract_tar(archive, dest)
    elif archive.endswith(".zip"):
        extract_zip(archive, dest)
