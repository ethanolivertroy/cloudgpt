from openai import OpenAI
import argparse
import re
import os
import csv
import random
from core.policy import *
from datetime import datetime
from google.cloud import resourcemanager_v3
from google.cloud import iam_v2
from google.cloud.iam_admin_v1 import IAMClient
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

parser = argparse.ArgumentParser(description='Retrieve all GCP policies and check for vulnerabilities')
parser.add_argument('--key', type=str, required=False, help='OpenAI API key (can also use OPENAI_API_KEY environment variable)')
parser.add_argument('--project-id', type=str, required=False, help='GCP project ID (can also use GCP_PROJECT_ID environment variable)')
parser.add_argument('--redact', action='store_true', default=True, help='Redact sensitive information in the policy document (default: True)')

results = []


def redact_policy(policy):
    new_policy = policy
    new_policy.original_document = str(policy.policy)

    # Replace project IDs with random values
    match = re.search(r'projects/([a-z0-9-]+)', new_policy.original_document)
    if match:
        original_project = match.group(1)
        new_project = f"project-{random.randint(10000, 99999)}"
        new_policy.map_accounts(original_project, new_project)
        new_policy.redacted_document = new_policy.original_document.replace(original_project, new_project)
    else:
        new_policy.redacted_document = new_policy.original_document

    return new_policy


def check_policy(policy, openai_client):
    prompt = f'Does this GCP policy have any security vulnerabilities: \n{policy.redacted_document}'
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
    header = ['project_id', 'policy_type', 'name', 'vulnerable', 'policy', 'mappings']
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
                'project_id': data.project_id,
                'policy_type': data.policy_type,
                'name': data.name,
                'vulnerable': data.ai_response,
                'policy': data.redacted_document,
                'mappings': mappings
            }
            writer.writerow(row)


def log(data):
    print(f'[*] {data}')


def scan_project_iam_policies(project_id, args):
    iam_client = IAMClient()
    
    # Get IAM policy
    resource_name = f'projects/{project_id}'
    try:
        policy = iam_client.get_iam_policy(request={'resource': resource_name})
        
        p = Policy()
        p.project_id = project_id
        p.policy_type = "IAM"
        p.name = f"{project_id}-iam-policy"
        p.policy = policy

        if args.redact:
            p = redact_policy(p)
            p = check_policy(p, openai_client)

        results.append(p)

    except Exception as e:
        log(f"Error scanning IAM policies for project {project_id}: {str(e)}")


def scan_org_policies(project_id, args):
    client = resourcemanager_v3.OrgPolicyClient()
    
    # List constraints
    request = resourcemanager_v3.ListConstraintsRequest(
        parent=f"projects/{project_id}",
    )
    
    try:
        constraints_page = client.list_constraints(request=request)
        
        for constraint in constraints_page:
            # Get policy for each constraint
            policy_request = resourcemanager_v3.GetPolicyRequest(
                name=f"projects/{project_id}/policies/{constraint.name}"
            )
            
            try:
                policy = client.get_policy(request=policy_request)
                
                p = Policy()
                p.project_id = project_id
                p.policy_type = "Organization"
                p.name = constraint.name
                p.policy = policy
                
                if args.redact:
                    p = redact_policy(p)
                    p = check_policy(p, openai_client)

                results.append(p)

            except Exception as e:
                log(f"Error getting policy for constraint {constraint.name}: {str(e)}")
                
    except Exception as e:
        log(f"Error listing constraints for project {project_id}: {str(e)}")


def main(args):
    # Get API key with priority: CLI arg > environment variable
    api_key = args.key or os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OpenAI API key is required. Provide it via --key argument or OPENAI_API_KEY environment variable.")

    # Get project ID with priority: CLI arg > environment variable
    project_id = args.project_id or os.getenv('GCP_PROJECT_ID')
    if not project_id:
        raise ValueError("GCP project ID is required. Provide it via --project-id argument or GCP_PROJECT_ID environment variable.")

    openai_client = OpenAI(api_key=api_key)
    scan_utc = datetime.utcnow().strftime("%Y-%m-%d-%H%MZ")
    
    log(f'Retrieving and redacting policies for GCP project: {project_id}')
    
    # Scan IAM policies
    scan_project_iam_policies(project_id, args)
    
    # Scan organization policies
    scan_org_policies(project_id, args)
    
    preserve(f'cache/{project_id}_{scan_utc}.csv', results)


if __name__ == '__main__':
    args = parser.parse_args()
    main(args)