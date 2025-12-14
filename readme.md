CloudGPT
==================

## Multi-Cloud Policy Vulnerability Scanner ##
Scan AWS, Azure, and GCP policies for vulnerabilities using AI.

This tool automatically redacts sensitive information like account numbers and project IDs by replacing them with randomly generated values before sending the policies for analysis. Knowledge of a vulnerable policy without knowledge of the specific account that has the policy provisioned is useless to the AI service. Additionally, the internal prompt has continually returned responses starting with Yes or No, therefore, we parse this portion of the response to determine vulnerability. Those using the tool should manually review the responses in the output to determine context of the response. It's not perfect but it's absolutely helpful.

## Credits ##
Originally created by [Mike Felch (@ustayready)](https://twitter.com/ustayready) - [Original Repository](https://github.com/ustayready/cloudgpt) 

## Basic Usage ##
### Requires OpenAI API key

### AWS Scanner
```
usage: aws-scan.py [-h] --key KEY [--profile PROFILE] [--redact]

Retrieve all customer managed AWS policies and check the default policy version for vulnerabilities

optional arguments:
  -h, --help         show this help message and exit
  --key KEY          OpenAI API key
  --profile PROFILE  AWS profile name to use (default: default)
  --redact           Redact sensitive information in the policy document (default: True)
```
*python aws-scan.py --key ABC --profile AWSPROFILE*

### Azure Scanner
```
usage: azure-scan.py [-h] --key KEY --subscription-id SUBSCRIPTION_ID [--redact]

Retrieve all Azure policies and check for vulnerabilities

optional arguments:
  -h, --help            show this help message and exit
  --key KEY             OpenAI API key
  --subscription-id SUBSCRIPTION_ID
                        Azure subscription ID
  --redact              Redact sensitive information in the policy document (default: True)
```
*python azure-scan.py --key ABC --subscription-id YOUR_SUBSCRIPTION_ID*

### GCP Scanner
```
usage: gcp-scan.py [-h] --key KEY [--project-id PROJECT_ID] [--redact]

Retrieve all GCP policies and check for vulnerabilities

optional arguments:
  -h, --help               show this help message and exit
  --key KEY                OpenAI API key
  --project-id PROJECT_ID  GCP project ID (default: uses gcloud default)
  --redact                 Redact sensitive information in the policy document (default: True)
```
*python gcp-scan.py --key ABC --project-id YOUR_PROJECT_ID*
         
## Installation ##
You can install and run with the following command:

```bash
$ git clone https://github.com/ustayready/cloudgpt
$ cd cloudgpt
~/cloudgpt $ virtualenv -p python3 .
~/cloudgpt $ source bin/activate
(cloudgpt) ~/cloudgpt $ pip install -r requirements.txt
```

## What's New in 2025 ##
- Added support for Google Cloud Platform (GCP) policy scanning
- Updated Azure scanning to support modern resource groups
- Enhanced core policy model to support all three cloud platforms
- Updated to use the latest Google Cloud and Azure SDKs




