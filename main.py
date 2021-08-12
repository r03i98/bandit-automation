#!/usr/bin/python
import os
import json
import argparse
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

    def manual_pt(self, filename,line_number, manual_test_reult):
        # This function add to a finding if a manual pt test is valid or not.
        with open('results.json', "r") as file:
            data = json.load(file)
            manual_pt_object = {'manaul_pt_valid':manual_test_reult}
            for i in data['results']:
                if filename in str(i['filename']) and line_number in str(i['line_number']):
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

    def show_info(self, functionNode):
        # This function outputs functions an args of functions to json
        functions_json = {"Function name": functionNode.name,
                          "Args": []}

        for arg in functionNode.args.args:
            functions_json['Args'].append(arg.arg)
        return functions_json

    def classes_functions_extract(self, f):
        # this function extract all classes methods and functions from a specifiec file
        myjson = {"classes": [],
                  "functions": []}
        filename = f
        with open(filename) as file:
            node = ast.parse(file.read())

        functions = [n for n in node.body if isinstance(n, ast.FunctionDef)]
        classes = [n for n in node.body if isinstance(n, ast.ClassDef)]
        for class_ in classes:
            tmpjson = {"class_name": class_.name,
                       "methods": []}
            methods = [n for n in class_.body if isinstance(n, ast.FunctionDef)]
            for method in methods:
                tmpjson["methods"].append(self.show_info(method))
            myjson["classes"].append(tmpjson)
        for function in functions:
            myjson["functions"].append(self.show_info(function))
        return myjson

    def added_value(self):
        # this function is adding each findings dependencies, classes, methods, and functions in related code file
        with open('results.json', "r") as file:
            data = json.load(file)
            results = data['results']
            for result in results:
                # This part add all dependecies
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
                # this part add all classes methods and functions
                result.update(self.classes_functions_extract(filepath))
                with open('results.json', "w") as file:
                    json.dump(data, file, indent=4)


if __name__ == "__main__":
    myclass = AutoBandit()
    parser = argparse.ArgumentParser()
    parser.add_argument('--validate',action='store_true', help='Use this option to add manual pt validate to a finding')
    parser.add_argument('--filename', type=str, help='chose a file to validate manual pt')
    parser.add_argument('--line_number', type=str, help='specify the vulnerable line')
    parser.add_argument('--pt', type=str, help='define if a vuln is valid after manual test (yes/no)')
    args = parser.parse_args()
    if args.validate:
        myclass.manual_pt(args.filename,args.line_number,args.pt)
    else:
        myclass.bandit_command()
        myclass.added_value()