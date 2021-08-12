#!/usr/bin/python
import os
import json
import argparse
from importlib.machinery import SourceFileLoader
import ast

# This script automate bandit SAST tool on given python apps.
# To use it put the desierd app inside the vuln_apps folder and run it.
# more instructions can be found on the README file.

class AutoBandit:
    def __init__(self):
        self.results = {}
        self.modules = set()

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

    def visit_Import(self, node):
        # function thats needed to add modules names to findings (i added from a forum)
        for name in node.names:
            self.modules.add(name.name.split(".")[0])

    def visit_ImportFrom(self,node):
        # function thats needed to add modules names to findings (i added from a forum)
        if node.module is not None and node.level == 0:
            self.modules.add(node.module.split(".")[0])

    def added_value(self):
        # this function is adding each findings dependencies in related code and  TODO: add also functions from the file
        with open('results.json', "r") as file:
            data = json.load(file)
            results = data['results']
            for result in results:
                file_dependencies = {'file_dependencies':[]}
                filepath = result['filename']
                node_iter = ast.NodeVisitor()
                node_iter.visit_Import = self.visit_Import
                node_iter.visit_ImportFrom = self.visit_ImportFrom
                with open(filepath) as f:
                    node_iter.visit(ast.parse(f.read()))
                for dependency in self.modules:
                    file_dependencies['file_dependencies'].append(dependency)
                result.update(file_dependencies)
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
    myclass.added_value()