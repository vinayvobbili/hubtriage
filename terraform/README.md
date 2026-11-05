# The organization, in stages

| Stage | Runs as | Builds |
|---|---|---|
| `00-org` | your Identity Center session, management account | budget, organization (imported), centralized root access, OUs, the security and workload accounts, delegated admins for GuardDuty and CloudTrail, SCPs |
| `10-security` | the same session, assuming `OrganizationAccountAccessRole` into security | GuardDuty org configuration, the security account's hub followed by its delegation, Security Hub members, the organization trail and its bucket, EventBridge → SQS, email alerts, the `hubtriage-agent` role, `hubtriage-enrich` |
| `20-workload` | the same, into workload | `hubtriage-enrich` |

Hub before spokes: each stage reads the previous stage's outputs from its local state file.
State and `terraform.tfvars` are git-ignored, and `tests/test_hygiene.py` fails if either is
ever tracked.

## Before the first apply (done by hand, once)

1. **Sign up** at aws.amazon.com with an email used only for this, and choose the **Paid**
   plan. Joining or creating an organization moves a Free-plan account to Paid anyway, and
   its credits expire when it does.
2. **Secure root**: add MFA (a passkey or a hardware key) right away. Create no access keys
   for root.
3. **Billing access**: Account → *IAM user and role access to Billing information* →
   Activate, so your Identity Center session can see the budget.
4. **IAM Identity Center** in us-east-1 → Enable. This creates the organization with all
   features. Add yourself as a user with MFA, create an `AdministratorAccess` permission
   set, and assign it to the management account.
5. Sign out of root and stay signed out. From here on: `aws configure sso`, then
   `aws sso login --profile <name>`.
6. Copy `00-org/terraform.tfvars.example` to `00-org/terraform.tfvars` and fill it in. The
   organization id is on the Organizations console page. Each account email must be unique
   across AWS; `+` aliases of one address work.

## Apply

```bash
export AWS_PROFILE=<your sso profile>
terraform -chdir=00-org init && terraform -chdir=00-org apply
terraform -chdir=10-security init && terraform -chdir=10-security apply
terraform -chdir=20-workload init && terraform -chdir=20-workload apply
```

Stage 10 needs its own `terraform.tfvars` too, copied from the example, for the alert address.
After it applies, click the confirmation link AWS emails there, or no alert is delivered.

Read the plan before each apply. Stage 00's import should show the organization as
*imported*, not *created*, and its service-access list as the complete set.
