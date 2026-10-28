# Deploying to Azure

How to stand up a Firewall Rule Review environment (staging or prod) in an Azure subscription
and release to it. Architecture: [ARCHITECTURE.md](ARCHITECTURE.md). Operations:
[RUNBOOK.md](RUNBOOK.md). The older CLI script and guide (`scripts/azure/deploy.sh`,
[../DEPLOY-AZURE.md](../DEPLOY-AZURE.md)) remain for the demo deployment; this guide is the
production path.

## What gets created

`infra/azure/` (Terraform) creates, per environment, in resource group `rg-frr-<env>`:

| Resource | Purpose |
|---|---|
| VNet with subnets for Container Apps, PostgreSQL and private endpoints; private DNS zones | Private networking |
| PostgreSQL Flexible Server 16, private access only | System of record; 14-day backups (geo-redundant in prod); zone-redundant HA when `db_high_availability = true`; pgvector allowed |
| Storage account (shared keys off, public network off) + private endpoint | Uploaded exports and snapshot artifacts, AAD-only |
| Key Vault (RBAC, purge protection) + private endpoint | Every secret; Container Apps read them by reference through managed identities |
| Managed identities `backend`, `frontend`, `migrate` | One per role; least privilege |
| Container Registry | Images, pulled by managed identity, referenced by digest |
| Container Apps environment (VNet-integrated): `-api` (internal ingress), `-worker` (no ingress, KEDA queue-depth scaling), `-web` (public) | The application |
| Container Apps job `-migrate` | Migrations and the post-deploy smoke test |
| Log Analytics + Application Insights + metric alerts | API 5xx, worker down, database CPU |

The model provider is the subscription's own **Azure AI Foundry** deployment
(`azure_ai_endpoint` / `azure_ai_deployment`); the backend identity is granted
*Cognitive Services OpenAI User* on the account given in `azure_ai_account_id`. BYOK keys
are optional (`byok_secrets`).

## One-time setup

Run as a subscription Owner once per subscription.

**1. Register providers and create Terraform state storage**

```bash
SUB=<subscription-id>; LOC=westeurope
az account set -s $SUB
for p in Microsoft.App Microsoft.DBforPostgreSQL Microsoft.KeyVault Microsoft.ContainerRegistry \
  Microsoft.Storage Microsoft.OperationalInsights Microsoft.Insights Microsoft.Network; do
  az provider register -n $p --wait; done
az group create -n rg-frr-tfstate -l $LOC
az storage account create -n <tfstateaccount> -g rg-frr-tfstate -l $LOC --sku Standard_ZRS \
  --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access false
az storage account blob-service-properties update -n <tfstateaccount> -g rg-frr-tfstate \
  --enable-versioning true --enable-delete-retention true --delete-retention-days 30
az storage container create -n tfstate --account-name <tfstateaccount> --auth-mode login
```

**2. Create the deploy identity and trust GitHub (federated credential, no secret)**

```bash
APP=$(az ad app create --display-name frr-deployer --query appId -o tsv)
az ad sp create --id $APP
az ad app federated-credential create --id $APP --parameters '{
  "name": "github-staging", "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<org>/<repo>:environment:azure-staging", "audiences": ["api://AzureADTokenExchange"]}'
# repeat with subject ...:environment:azure-prod for prod
az role assignment create --assignee $APP --role Owner --scope /subscriptions/$SUB
az role assignment create --assignee $APP --role "Storage Blob Data Contributor" \
  --scope $(az storage account show -n <tfstateaccount> -g rg-frr-tfstate --query id -o tsv)
```

*Owner* is needed because Terraform creates role assignments. To narrow it, use
*Contributor* plus *Role Based Access Control Administrator* constrained to the roles in
`infra/azure/iam.tf`.

**3. Register the SSO application.** Redirect URI: `https://<app-domain>/api/auth/callback/autox`.
See [../SSO.md](../SSO.md).

**4. Configure the GitHub environment** `azure-staging` (and `azure-prod`, with required reviewers)

| Kind | Name | Value |
|---|---|---|
| var | `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | the deploy app from step 2 |
| var | `TF_STATE_RG`, `TF_STATE_ACCOUNT`, `TF_STATE_CONTAINER` | `rg-frr-tfstate`, `<tfstateaccount>`, `tfstate` |
| var | `RESOURCE_GROUP` | `rg-frr-<env>` |
| var | `ACR_NAME` | registry name (from `terraform output registry` after the first apply) |
| var | `TFVARS` | non-secret variables, see below |
| secret | `SSO_CLIENT_SECRET` | from step 3 |
| secret | `BYOK_SECRETS_JSON` | optional |

```hcl
location             = "westeurope"
app_url              = "https://frr-staging.example.com"
sso_issuer           = "https://login.example.com/oauth2"
sso_client_id        = "<client-id>"
azure_ai_endpoint    = "https://<account>.cognitiveservices.azure.com/"
azure_ai_deployment  = "gpt-4.1-mini"
azure_ai_account_id  = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.CognitiveServices/accounts/<account>"
db_high_availability = false   # true for prod
alert_emails         = ["oncall@example.com"]
```

**First apply.** The registry does not exist until Terraform creates it, so the very first
apply runs from a workstation with placeholder digests to create the registry, then the
workflow takes over:

```bash
cd infra/azure
terraform init -backend-config="resource_group_name=rg-frr-tfstate" \
  -backend-config="storage_account_name=<tfstateaccount>" -backend-config="container_name=tfstate" \
  -backend-config="key=frr/staging.tfstate" -backend-config="use_azuread_auth=true"
terraform apply -target=azurerm_container_registry.acr -var-file=staging.tfvars \
  -var subscription_id=$SUB -var env=staging -var "operator_ip_cidrs=[\"$(curl -s https://api.ipify.org)/32\"]" \
  -var backend_image=x/b@sha256:$(printf '0%.0s' {1..64}) -var frontend_image=x/f@sha256:$(printf '0%.0s' {1..64})
```

Set `ACR_NAME` from `terraform output registry`, then run the workflow.

## Releasing

GitHub → Actions → **Deploy (Azure)** → environment. The workflow builds and pushes both
images once, runs migrations on the new image, applies Terraform with the new digests, runs
the smoke test as a job execution inside the VNet, and checks the public URL. The runner's
IP is added to Key Vault's allow-list for the apply only.

### First-release checks

- [ ] `terraform output frontend_url` opens the sign-in page; SSO round-trip works.
- [ ] Admin → AI configuration shows provider **azure** with the identity credential OK.
- [ ] `/api/health` reports `environment: <env>`, `platform: azure`, no degraded reasons.
- [ ] With `domain` set: DNS CNAME + TXT validation done, `app_url` = `https://<domain>`, and a
      request to the `-web` hostname directly returns 404.
- [ ] Alerts route to the on-call address.

## Capacity and cost levers

| Variable | Default | Notes |
|---|---|---|
| `api_min_replicas` / `api_max_replicas` | 1 / 10 | Scales on 40 concurrent requests per replica |
| `worker_max_replicas` | 4 | KEDA adds a replica per `worker_jobs_per_replica` (5) ready jobs; minimum 1 |
| `db_sku` | `GP_Standard_D2ds_v5` | Raise before raising replica counts |
| `db_high_availability` | true | Zone-redundant standby |

The connection budget is the same as on GCP: keep
`api replicas × api_processes × 8 + worker replicas × worker_concurrency × 2` within the
server's `max_connections` for the chosen SKU, or enable the server's built-in PgBouncer.

## Edge: Front Door + WAF

Set `domain` to put Azure Front Door Premium in front of `-web`: managed OWASP rules and bot
protection in Prevention mode, a per-client-IP rate limit (`edge_rate_limit_per_minute`),
HTTPS only. CNAME the domain to the `front_door_endpoint` output and add the TXT validation
record Front Door shows for the custom domain; the managed certificate follows.

Container Apps ingress cannot restrict callers to Front Door's service tag, so the frontend
itself refuses any request without this profile's `X-Azure-FDID` (`NPR_EDGE_ID`, set by
Terraform), with a 404. Static assets and `/api/auth` are excluded from the middleware and
therefore from that check; everything that reaches the API passes through it.
