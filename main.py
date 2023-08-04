import csv
import json
import os

import requests
import typer

policy_cache = {}

class ComplianceHelper():
    token: str = ""
    stack: str = ""

    @property
    def headers(self):
        return {
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'x-redlock-auth': self.token
            }

    def __init__(self, stack: str):
        self.stack = stack
        self.get_token()

    def get_token(self):
        url = f"https://{self.stack}.prismacloud.io/login"
        payload = json.dumps({
            "username": os.environ["PC_USER"],
            "password": os.environ["PC_PASS"]
        })
        headers = {
            'Content-Type': 'application/json'
        }
        response = requests.request("POST", url, headers=headers, data=payload)
        response.raise_for_status()
        self.token = response.json()['token']

    def get_compliance_finding(self, standard: str, compliance_requirement: str, compliance_section: str, scan_status: str, account_group: str, limit: int = 1000):
        url = f"https://{self.stack}.prismacloud.io/resource/scan_info"
        payload = json.dumps({
        "filters": [  # Fine could be done based on https://prisma.pan.dev/api/cloud/cspm/asset-explorer/#operation/get-resource-scan-info
            {
            "name": "includeEventForeignEntities",
            "operator": "=",
            "value": "true"
            },
            {
            "name": "account.group",
            "operator": "=",
            "value": account_group
            },
            {
            "name": "policy.complianceSection",
            "operator": "=",
            "value": compliance_section
            },
            {
            "name": "policy.complianceRequirement",
            "operator": "=",
            "value": compliance_requirement
            },
            {
            "name": "policy.complianceStandard",
            "operator": "=",
            "value": standard
            },
            {
            "name": "scan.status",
            "operator": "=",
            "value": scan_status
            },
            {
            "name": "decorateWithDerivedRRN",
            "operator": "=",
            "value": True
            }
        ],
        "limit": limit,
        "timeRange": {
            "type": "to_now",  # Latest results
            "value": "epoch"
        }
        })

        response = requests.request("POST", url, headers=self.headers, data=payload)
        response.raise_for_status()
        return response.json()

    def get_compliance_requirements(self, standard_id: str):
        url = f"https://{self.stack}.prismacloud.io/compliance/{standard_id}/requirement"
        response = requests.request("GET", url, headers=self.headers, data={})
        response.raise_for_status()
        return response.json()

    def get_compliance_standard(self, standard_name: str):
        url = f"https://{self.stack}.prismacloud.io/compliance"
        response = requests.request("GET", url, headers=self.headers, data={})
        response.raise_for_status()
        for standard in response.json():
            if standard.get('name', '') == standard_name:
                return standard

    def get_compliance_section(self, requirement_id: str):
        url = f"https://{self.stack}.prismacloud.io/compliance/{requirement_id}/section"
        response = requests.request("GET", url, headers=self.headers, data={})
        response.raise_for_status()
        return response.json()

    def get_policy_remediation(self, policy_id: str):
        global policy_cache
        if policy_cache.get(policy_id, False) is False:
            # Policy cache setup
            url = f"https://{self.stack}.prismacloud.io/policy/{policy_id}"

            response = requests.request("GET", url, headers=self.headers, data={})
            response.raise_for_status()

            policy_cache[policy_id] = response.json()

        return policy_cache[policy_id]

app = typer.Typer(help="Compliance Exporter")

@app.command()
def main(
    standard_name: str = typer.Option("ISO 27001:2013", help="ISO Standard for export"),
    account_group: str = typer.Option("PCS Demo Environments", help="Account Group for export"),
    output_file: str = typer.Option("out.csv", help="Output file"),
    stack_name: str = typer.Option("api.eu", help="Prisma Cloud stack")
    ):

    helper = ComplianceHelper(stack=stack_name)

    # Main logic
    # Get compliance standard information
    standard = helper.get_compliance_standard(standard_name=standard_name)

    print("Starting csv generation")
    with open(output_file, "w") as csv_file:
        writer = csv.writer(csv_file, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(
            [
                "standard", "requirement_name", "requirement_id",
                "section_id", "account_name", "account_id",
                "provider", "rrn", "resource_name", "scan_status", "policies"
            ]
        )

        # Get all requirements from compliance standard
        requirements = helper.get_compliance_requirements(standard_id=standard['id'])
        for requirement in requirements:
            # Get all sections from compliance standard
            sections = helper.get_compliance_section(requirement_id=requirement['id'])
            for section in sections:
                def get_results(requirement, section, scan_status: str):
                    """ Helper function to get compliance findings """
                    findings = helper.get_compliance_finding(
                        standard["name"],
                        requirement['name'],
                        section['sectionId'],
                        scan_status,
                        account_group
                    )

                    for resource in findings.get('resources', []):
                        policy_results = []
                        for policy in resource['scannedPolicies']:
                            policy_results.append(
                                {
                                    'name': policy['name'] if policy['id'] in section['associatedPolicyIds'] else "",
                                    'recommendation': helper.get_policy_remediation(policy['id'])['recommendation']
                                }
                                )
                        writer.writerow(
                            [
                                standard['name'] ,requirement['name'],requirement['requirementId'],
                                section['sectionId'],resource['accountName'],
                                resource['accountId'],resource['cloudType'],
                                resource.get('rrn', resource['id']), resource['name'],
                                scan_status, str(policy_results)
                            ]
                        )

                # Get finding results for given section of compliance standard
                get_results(requirement, section, "failed")
                get_results(requirement, section, "passed")

    print("CSV generation finished")

if __name__ == "__main__":
    app()
