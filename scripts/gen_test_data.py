import glob
import os
import sys

# Import the required functions and modules
import json
import shutil
import tempfile
import zipfile
from os.path import join, exists
from sign import sign

def createTestZipFile(output_file):
    # Create a new zip file with the modified contents
    nzip = output_file.rstrip(".zip")
    nzip = nzip+".new"
    shutil.make_archive(nzip, 'zip', 'temp')
    if os.path.exists(output_file):
        os.remove(f'{output_file}')
    os.rename(f'{nzip}.zip', f'{output_file}')

def gen_no_metainf_report_json(input_file, output_file):
    print("Generating test case: no META-INF/reports.json")
    with zipfile.ZipFile(input_file, 'r') as zip_ref:
        # Extract the contents of the input zip file
        zip_ref.extractall('temp')

    # Remove the reports.json file from META-INF directory
    rep_json_paths = glob.glob('temp/*/META-INF/reports.json')
    for reports_json_path in rep_json_paths:
        if os.path.exists(reports_json_path):
            print("Removing reports.json file")
            os.remove(reports_json_path)

    createTestZipFile(output_file)

    print("Generated test case: no META-INF/reports.json")

    # Cleanup temporary directory
    shutil.rmtree('temp')
    print("Cleaning up temporary directory")

def gen_missing_signature(input_file, output_file):
    with zipfile.ZipFile(input_file, 'r') as zip_ref:
        # Extract the contents of the input zip file
        zip_ref.extractall('temp')

    # Load the manifest from reports.json
    rep_json_paths = glob.glob('temp/*/META-INF/reports.json')
    for reports_json_path in rep_json_paths:
        if os.path.exists(reports_json_path):
            print("Removing signatures from reports.json file")
            with open(reports_json_path, 'r') as manifest_file:
                manifest = json.load(manifest_file)

                # Remove one signature entry from the manifest
                if "signatures" in manifest["documentInfo"]:
                    signatures = manifest["documentInfo"]["signatures"]
                    if len(signatures) > 0:
                        signatures.pop(0)

                # Save the modified manifest back to reports.json
                with open(reports_json_path, 'w') as manifest_file:
                    json.dump(manifest, manifest_file)

    # Create a new zip file with the modified contents
    createTestZipFile(output_file)

    # Cleanup temporary directory
    shutil.rmtree('temp')

def gen_no_signatures(input_file, output_file):
    with zipfile.ZipFile(input_file, 'r') as zip_ref:
        # Extract the contents of the input zip file
        zip_ref.extractall('temp')

    # Load the manifest from reports.json
    rep_json_paths = glob.glob('temp/*/META-INF/reports.json')
    for reports_json_path in rep_json_paths:
        if os.path.exists(reports_json_path):
            print("Removing signatures from reports.json file")
            with open(reports_json_path, 'r') as manifest_file:
                manifest = json.load(manifest_file)

                # Remove one signature entry from the manifest
                if "signatures" in manifest["documentInfo"]:
                    signatures = manifest["documentInfo"]["signatures"]
                    if len(signatures) > 0:
                        signatures.clear()

                # Save the modified manifest back to reports.json
                with open(reports_json_path, 'w') as manifest_file:
                    json.dump(manifest, manifest_file)

    # Create a new zip file with the modified contents
    createTestZipFile(output_file)

    # Cleanup temporary directory
    shutil.rmtree('temp')

def process_test_cases(unsigned_file):
    # Create the directory for test case files if it doesn't exist
    output_dir = "tests/data/report/failures/"
    os.makedirs(output_dir, exist_ok=True)

    # Generate signed report
    signed_file = "signed_report.zip"
    sign(unsigned_file, signed_file)

    # Apply each test case function to the signed report
    gen_no_metainf_report_json(signed_file, output_dir + "test_noMetaInfReportJson.zip")
    gen_missing_signature(signed_file, output_dir + "test_MetaInfReportJson_missingSig.zip")
    gen_no_signatures(signed_file, output_dir + "test_MetaInfReportJson_noSigs.zip")

    # Clean up the signed report file
    os.remove(signed_file)

if __name__ == "__main__":
    # Check if the unsigned zip file argument is provided
    if len(sys.argv) != 2:
        print("Usage: python gen_test_data.py <unsigned_zip_file>")
        sys.exit(1)

    unsigned_zip_file = sys.argv[1]
    process_test_cases(unsigned_zip_file)