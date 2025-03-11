class Policy:
    def __init__(self):
        # Common fields
        self.name = None
        self.policy = None
        self.original_document = None
        self.redacted_document = None
        self.ai_response = None
        self.account_mapping = {}
        
        # AWS specific
        self.account = None
        self.arn = None
        self.version = None
        
        # Azure specific
        self.subscription_id = None
        self.resource_group = None
        self.id = None
        
        # GCP specific
        self.project_id = None
        self.policy_type = None

    def __repr__(self):
        return 'Policy()'
    def __str__(self):
        return f'<Policy name:{self.name}>'

    def map_accounts(self, old, new):
        self.account_mapping[old] = new

    def retrieve_mappings(self):
        maps = []
        for k,v in self.account_mapping.items():
            maps.append(f'{k}->{v}')
        return ', '.join(maps)

    def is_changed(self):
        return self.original_document != self.redacted_document

    def is_vulnerable(self):
        vulnerable = 'CHECK CSV'
        
        if 'Yes,' in self.ai_response:
            vulnerable = 'VULNERABLE'
        elif 'No,' in self.ai_response:
            vulnerable = 'NOT VULNERABLE'

        return vulnerable
