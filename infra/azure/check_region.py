"""Read actual subscription capabilities before attempting billable provisioning.

ARM template validation alone can pass even when PostgreSQL provisioning is restricted.
This check never creates resources or prints credentials.
"""

import argparse
import json
import shutil
import subprocess


def check_capabilities(capabilities, version="17", sku="Standard_B1ms"):
    errors = []
    if not capabilities:
        return ["Azure returned no PostgreSQL capabilities"]
    for capability in capabilities:
        restricted = any(feature.get("name") == "OfferRestricted"
                         and feature.get("status") == "Enabled"
                         for feature in capability.get("supportedFeatures", []))
        if restricted:
            errors.append(capability.get("reason") or "Subscription offer is restricted")
        versions = {item["name"] for item in capability.get("supportedServerVersions", [])}
        if version not in versions:
            errors.append(f"PostgreSQL {version} is not offered to this subscription in this region")
        skus = {item["name"] for edition in capability.get("supportedServerEditions", [])
                for item in edition.get("supportedServerSkus", [])}
        if sku not in skus:
            errors.append(f"{sku} is not offered to this subscription in this region")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--location", required=True)
    args = parser.parse_args()
    cli = shutil.which("az")
    if cli is None:
        parser.error("Azure CLI must be installed and on PATH")
    result = subprocess.run([cli, "postgres", "flexible-server", "list-skus",
                             "--subscription", args.subscription, "--location", args.location,
                             "--output", "json", "--only-show-errors"],
                            capture_output=True, text=True, check=True)
    errors = check_capabilities(json.loads(result.stdout))
    print(json.dumps({"location": args.location, "postgresql_capabilities_passed": not errors,
                      "errors": errors, "other_resource_quotas_verified": False}, indent=2))
    raise SystemExit(1 if errors else 0)


if __name__ == "__main__":
    main()
