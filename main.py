import os
import json
import argparse

class AutoBandit:
    def __init__(self):
        self.results = {}

    def bandit_command(self):
        os.system('bandit --quiet -f json -r vuln_apps/ -o results.json')

    def manual_pt(self):

    def json_manipulte(self):
        f = open('results.json')
        data = json.load(f)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--pt', type=int, help='Listen port. Default: 4000', default=4000)
    args = parser.parse_args()

    myclass = AutoBandit()
    myclass.bandit_command()