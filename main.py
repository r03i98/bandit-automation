import os
import json

class AutoBandit:
    def __init__(self):
        self.results = {}

    def bandit_command(self):
        os.system('bandit --quiet -f json -r vuln_apps/ -o results.json')

    def json_manipulte(self):
        f = open('results.json')
        data = json.load(f)


myclass = AutoBandit()
myclass.bandit_command()