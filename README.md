# Bandit automation

This script automate a bandit SAST scan on a given python web app (or multiple.) and also enrich the scan and give more insight on each finding.
Each finding is appended with the following information:
* The related py file dependencies
* The related py file classes, methods, and functions.
* The user can add with the cli manual pt results (valid or not)
* All the results are stored in json for future manipulation.

# Requriements

*the script was tested on macos 
* git
* python3
* bandit (```pip3 install bandit```)

# How does it works?

### Basic run

1. First of all you need to place the testing app inside the vuln_apps folder.
2. simpley run the script with
    ```
    python3 main.py
    ```
 
 ### Manual PT results
 1. Run the app with the following flags
    ```
    python3 main.py --validate --filename <VALIDATED_FILENAME> --line_number <VALIDATED_LINE_NUMBER> --pt <YES/NO>
    ```
