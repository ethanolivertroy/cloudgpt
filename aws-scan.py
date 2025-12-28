from openai import OpenAI
import boto3
import argparse
import re
import os
import csv
import random
from core.policy import *
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

parser = argparse.ArgumentParser(description='Retrieve all customer managed policies and check the default policy version for vulnerabilities')
parser.add_argument('--key', type=str, required=False, help='OpenAI API key (can also use OPENAI_API_KEY environment variable)')
parser.add_argument('--profile', type=str, default='default', help='AWS profile name to use (default: default)')
parser.add_argument('--redact', action='store_true', default=True, help='Redact sensitive information in the policy document (default: True)')

results = []


def redact_policy(policy):
    new_policy = policy
    new_policy.original_document = str(policy.policy)

    match = re.search(r'\b\d{12}\b', new_policy.original_document)
    if match:
        original_account = match.group()
        new_account = random.randint(100000000000, 999999999999)
        new_policy.map_accounts(original_account, new_account)
        new_policy.redacted_document = new_policy.original_document.replace(original_account, str(new_account))
    else:
        new_policy.redacted_document = new_policy.original_document

    return new_policy


def check_policy(policy, openai_client):
    prompt = f'Does this AWS policy have any security vulnerabilities: \n{policy.redacted_document}'
    response = openai_client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a cloud security expert. Analyze the policy and determine if it has security vulnerabilities. Start your response with 'Yes,' if it has vulnerabilities or 'No,' if it does not."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.5,
        max_tokens=1000,
        top_p=1,
        frequency_penalty=0.0,
        presence_penalty=0.0,
        stream=False,
    )
    policy.ai_response = response.choices[0].message.content.strip()
    is_vulnerable = policy.is_vulnerable()
    log(f'Policy {policy.name} [{is_vulnerable}]')

    return policy


def preserve(filename, results):
    header = ['account', 'name', 'arn', 'version', 'vulnerable', 'policy', 'mappings']
    mode = 'a' if os.path.exists(filename) else 'w'

    log(f'Saving scan: {filename}')

    os.makedirs('cache', exist_ok=True)

    with open(filename, mode) as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if mode == 'w':
            writer.writeheader()
            for data in results:
                mappings = '' if len(data.retrieve_mappings()) == 0 else data.retrieve_mappings()
                row = {
                    'account': data.account, 'name': data.name, 'arn': data.arn,
                    'version': data.version, 'vulnerable': data.ai_response, 'policy':
                    data.redacted_document, 'mappings': mappings
                }
                writer.writerow(row)


def log(data):
    print(f'[*] {data}')


def main(args):
    # Get API key with priority: CLI arg > environment variable
    api_key = args.key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OpenAI API key is required. Provide it via --key argument or OPENAI_API_KEY environment variable.")

    openai_client = OpenAI(api_key=api_key)
    session = boto3.Session(profile_name=args.profile)
    scan_utc = datetime.utcnow().strftime("%Y-%m-%d-%H%MZ")

    client = session.client('iam')
    account = session.client('sts').get_caller_identity().get('Account')

    log(f'Retrieving and redacting policies for account: {account}')

    paginator = client.get_paginator('list_policies')
    response_iterator = paginator.paginate(Scope='Local', OnlyAttached=False)
    for response in response_iterator:
        for policy in response['Policies']:

            policy_name = policy['PolicyName']

            policy_arn = policy['Arn']
            policy_version = client.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
            default_version = policy_version['PolicyVersion']['VersionId']

            if not policy_arn.startswith("arn:aws:iam::aws"):
                policy_document = ''

                p = Policy()
                p.account = account
                p.arn = policy_arn
                p.name = policy_name
                p.policy = policy_version['PolicyVersion']['Document']
                p.version = default_version

                if args.redact:
                    p = redact_policy(p)
                    p = check_policy(p, openai_client)

                results.append(p)

    preserve(f'cache/{account}_{scan_utc}.csv', results)


if __name__ == '__main__':
    args = parser.parse_args()
    main(args)


