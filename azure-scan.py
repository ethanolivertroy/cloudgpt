import os
import csv
import random
import argparse
import re
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from openai import OpenAI
from core.policy import Policy
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

parser = argparse.ArgumentParser(description='Retrieve all Azure policies and check for vulnerabilities')
parser.add_argument('--key', type=str, required=False, help='OpenAI API key (can also use OPENAI_API_KEY environment variable)')
parser.add_argument('--subscription-id', type=str, required=False, help='Azure subscription ID (can also use AZURE_SUBSCRIPTION_ID environment variable)')
parser.add_argument('--redact', action='store_true', default=True, help='Redact sensitive information in the policy document (default: True)')

results = []

def redact_policy(policy):
    new_policy = policy
    new_policy.original_document = str(policy.policy)

    # Replace sensitive information (Azure subscription IDs are UUIDs)
    # Pattern matches UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', new_policy.original_document, re.IGNORECASE)
    if match:
        original_subscription = match.group()
        # Generate a random UUID for redaction
        import uuid
        new_subscription = str(uuid.uuid4())
        new_policy.map_accounts(original_subscription, new_subscription)
        new_policy.redacted_document = new_policy.original_document.replace(original_subscription, new_subscription)
    else:
        new_policy.redacted_document = new_policy.original_document

    return new_policy

def check_policy(policy, openai_client):
    prompt = f'Does this Azure policy have any security vulnerabilities: \n{policy.redacted_document}'
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
    header = ['subscription_id', 'resource_group', 'name', 'id', 'vulnerable', 'policy', 'mappings']
    mode = 'a' if os.path.exists(filename) else 'w'

    log(f'Saving scan: {filename}')

    with open(filename, mode) as f:
        writer = csv.DictWriter(f, fieldnames=header)
        if mode == 'w':
            writer.writeheader()
        for data in results:
            mappings = '' if len(data.retrieve_mappings()) == 0 else data.retrieve_mappings()
            row = {
                'subscription_id': data.subscription_id, 'resource_group': data.resource_group, 'name': data.name,
                'id': data.id, 'vulnerable': data.ai_response, 'policy':
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

    # Get subscription ID with priority: CLI arg > environment variable
    subscription_id = args.subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
    if not subscription_id:
        raise ValueError("Azure subscription ID is required. Provide it via --subscription-id argument or AZURE_SUBSCRIPTION_ID environment variable.")

    openai_client = OpenAI(api_key=api_key)

    credential = DefaultAzureCredential()
    resource_client = ResourceManagementClient(credential, subscription_id)

    scan_utc = datetime.utcnow().strftime("%Y-%m-%d-%H%MZ")

    log(f'Retrieving and redacting policies for subscription: {subscription_id}')

    # Import the authorization management client
    from azure.mgmt.authorization import AuthorizationManagementClient
    authorization_client = AuthorizationManagementClient(credential, subscription_id)
    
    # Create cache directory if it doesn't exist
    os.makedirs('cache', exist_ok=True)
    
    # Iterate over all policies in all resource groups
    for group in resource_client.resource_groups.list():
        resource_group_name = group.name
        log(f'Scanning resource group: {resource_group_name}')
        
        # Get policy assignments for the resource group
        policy_assignments = authorization_client.policy_assignments.list_for_resource_group(
            resource_group_name=resource_group_name
        )
        
        for assignment in policy_assignments:
            policy_id = assignment.policy_definition_id
            
            try:
                # Extract policy definition ID
                definition_id = policy_id.split('/')[-1]
                
                # Get the policy definition
                policy_definition = authorization_client.policy_definitions.get(definition_id)
                
                p = Policy()
                p.subscription_id = subscription_id
                p.resource_group = resource_group_name
                p.name = assignment.name
                p.id = assignment.id
                p.policy = policy_definition.policy_rule
                
                if args.redact:
                    p = redact_policy(p)
                    p = check_policy(p, openai_client)

                results.append(p)

            except Exception as e:
                log(f'Error processing policy {assignment.name}: {str(e)}')
    
    # Also scan subscription-level policy assignments
    subscription_policies = authorization_client.policy_assignments.list_for_subscription()
    
    for assignment in subscription_policies:
        policy_id = assignment.policy_definition_id
        
        try:
            # Extract policy definition ID
            definition_id = policy_id.split('/')[-1]
            
            # Get the policy definition
            policy_definition = authorization_client.policy_definitions.get(definition_id)
            
            p = Policy()
            p.subscription_id = args.subscription_id
            p.resource_group = "subscription-level"
            p.name = assignment.name
            p.id = assignment.id
            p.policy = policy_definition.policy_rule
            
            if args.redact:
                p = redact_policy(p)
                p = check_policy(p, openai_client)

            results.append(p)

        except Exception as e:
            log(f'Error processing policy {assignment.name}: {str(e)}')
    
    scan_utc = datetime.utcnow().strftime("%Y-%m-%d-%H%MZ")
    preserve(f'cache/{subscription_id}_{scan_utc}.csv', results)

if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
