#!/usr/bin/python
import os
import json
import argparse

# This script automate bandit SAST tool on given python apps.
# To use it put the desierd app inside the vuln_apps folder and run it.
# more instructions can be found on the README file.

class AutoBandit:
    def __init__(self):
        self.results = {}

    def bandit_command(self):
        # This command just preform the bandit scan command directly from the os. (NOT SECURE AND MUST BE CHANGED! its a pilot only)
        os.system('bandit --quiet -f json -r vuln_apps/ -o results.json')

    def manual_pt(self, testid, manual_test_reult):
        # This function add to a finding if a manual pt test is valid or not.
        with open('results.json', "r") as file:
            data = json.load(file)
            manual_pt_object = {'manaul_pt_valid':manual_test_reult}
            for i in data['results']:
                if testid in str(i['test_id']):
                    i.update(manual_pt_object)
        with open('results.json', "w") as file:
            json.dump(data, file, indent=4)

if __name__ == "__main__":
    myclass = AutoBandit()
    myclass.bandit_command()
    parser = argparse.ArgumentParser()
    parser.add_argument('--validate',action='store_true', help='Use this option to add manual pt validate to a finding')
    parser.add_argument('--testid', type=str, help='chose a test id and add data to')
    parser.add_argument('--pt', type=str, help='define if a vuln is valid after manual test (yes/no)')
    args = parser.parse_args()
    if args.validate:
        myclass.manual_pt(args.testid,args.pt)
