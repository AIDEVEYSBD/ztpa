# Deploying to Google Cloud

How to stand up a Firewall Rule Review environment (staging or prod) in a GCP project and
release to it. Architecture and the reasons behind it: [ARCHITECTURE.md](ARCHITECTURE.md).
Operating it day to day: [RUNBOOK.md](RUNBOOK.md).

## What gets created

`infra/gcp/` (Terraform) creates, per environment:

| Resource | Purpose |
|---|---|
| VPC, subnet with Private Google Access, Cloud NAT | Private networking; outbound internet (SSO issuer) through NAT |
| Cloud SQL for PostgreSQL 16, private IP only | System of record; point-in-time recovery; regional HA when `db_high_availability = true` |
| GCS bucket (versioned, no public access) | Uploaded exports and published snapshot artifacts |
| Secret Manager secrets | DB URLs, proxy secret, artifact key, auth secret, SSO client secret, optional BYOK keys |
| Service accounts `backend`, `frontend`, `migrate` | One per role; no keys; least privilege |
| Artifact Registry repository | Images, referenced by digest |
| Cloud Run: `-api` (internal only), `-worker` (always on), `-web` (public), `-migrate` (job) | The application |
| Optional HTTPS load balancer + managed certificate + Cloud Armor | Custom domain, WAF, per-IP rate limit (set `domain`) |
| Alert policies | API 5xx rate, worker absent, database CPU |

The model provider is the project's own **Vertex AI** (`ADVISORY_PROVIDER=auto` picks it on
Cloud Run). BYOK keys are optional (`byok_secrets`).

## One-time setup

Run as a project owner (or equivalent) once per project.

**1. Enable the bootstrap APIs and create a Terraform state bucket**

```bash
PROJECT=<gcp-project-id>; REGION=europe-west4
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  cloudresourcemanager.googleapis.com storage.googleapis.com --project $PROJECT
gcloud storage buckets create gs://$PROJECT-tfstate --project $PROJECT --location $REGION \
  --uniform-bucket-level-access --public-access-prevention
gcloud storage buckets update gs://$PROJECT-tfstate --versioning
```

The state contains generated secrets. Only the deploy identity and break-glass admins
should be able to read this bucket.

**2. Create the deploy identity and trust GitHub (workload identity federation, no keys)**

```bash
gcloud iam service-accounts create frr-deployer --project $PROJECT
DEPLOYER=frr-deployer@$PROJECT.iam.gserviceaccount.com
for role in roles/run.admin roles/cloudsql.admin roles/secretmanager.admin \
  roles/storage.admin roles/artifactregistry.admin roles/compute.networkAdmin \
  roles/servicenetworking.networksAdmin roles/iam.serviceAccountAdmin \
  roles/iam.serviceAccountUser roles/resourcemanager.projectIamAdmin \
  roles/serviceusage.serviceUsageAdmin roles/monitoring.alertPolicyEditor \
  roles/compute.securityAdmin roles/compute.loadBalancerAdmin; do
  gcloud projects add-iam-policy-binding $PROJECT --member serviceAccount:$DEPLOYER --role $role
done

gcloud iam workload-identity-pools create github --location global --project $PROJECT
gcloud iam workload-identity-pools providers create-oidc github --location global \
  --workload-identity-pool github --project $PROJECT \
  --issuer-uri https://token.actions.githubusercontent.com \
  --attribute-mapping "google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition "assertion.repository=='<org>/<repo>'"
POOL=$(gcloud iam workload-identity-pools describe github --location global --project $PROJECT --format 'value(name)')
gcloud iam service-accounts add-iam-policy-binding $DEPLOYER --project $PROJECT \
  --role roles/iam.workloadIdentityUser \
  --member "principalSet://iam.googleapis.com/$POOL/attribute.repository/<org>/<repo>"
```

**3. Register the SSO application**

Redirect URI: `https://<app-domain>/api/auth/callback/autox`. Record the issuer, client id and
client secret. Role mapping is described in [../SSO.md](../SSO.md).

**4. Configure the GitHub environment** `gcp-staging` (and `gcp-prod`, with required reviewers)

| Kind | Name | Value |
|---|---|---|
| var | `GCP_PROJECT_ID` | the project id |
| var | `GCP_REGION` | e.g. `europe-west4` |
| var | `GCP_WIF_PROVIDER` | `projects/<number>/locations/global/workloadIdentityPools/github/providers/github` |
| var | `GCP_DEPLOY_SA` | `frr-deployer@<project>.iam.gserviceaccount.com` |
| var | `TF_STATE_BUCKET` | `<project>-tfstate` |
| var | `TFVARS` | the non-secret variables, see below |
| secret | `SSO_CLIENT_SECRET` | from step 3 |
| secret | `BYOK_SECRETS_JSON` | optional, e.g. `{"OPENAI_API_KEY":"…"}` |

`TFVARS` example (images, project, region and env are passed by the workflow):

```hcl
app_url              = "https://frr-staging.example.com"
domain               = "frr-staging.example.com"   # "" = use the run.app URL, no load balancer
sso_issuer           = "https://login.example.com/oauth2"
sso_client_id        = "<client-id>"
db_high_availability = false                        # true for prod
alert_channels       = ["projects/<project>/notificationChannels/<id>"]
```

## Releasing

GitHub → Actions → **Deploy (GCP)** → environment. The workflow:

1. builds and pushes both images once (with provenance and SBOM);
2. runs migrations on the **new** backend image before anything rolls
   (`migrate.py --bootstrap --ensure-app-role`, as the `migrate` identity);
3. applies Terraform with the new digests, rolling the API, worker and frontend;
4. runs the smoke test inside the VPC (`python -m src.smoke`: API liveness, migrations
   current, a worker completing a job) and checks the public URL.

The first release creates everything; expect 15–25 minutes, mostly Cloud SQL. With a
`domain`, point its A record at the `edge_ip` output; the managed certificate turns active
once DNS resolves (up to an hour).

### First-release checks

- [ ] `terraform output frontend_url` opens the sign-in page; SSO round-trip works.
- [ ] Admin → AI configuration shows provider **vertex** and a successful test call.
- [ ] `/api/health` (as admin, through the app) reports `environment: <env>`, `platform: gcp`,
      no degraded reasons.
- [ ] Alert policies have a notification channel.

## Manual deploy (no GitHub)

From a workstation with `gcloud auth application-default login` and Docker:

```bash
REPO=$REGION-docker.pkg.dev/$PROJECT/frr-staging
gcloud auth configure-docker $REGION-docker.pkg.dev
docker build --platform linux/amd64 -f backend/Dockerfile -t $REPO/backend:manual . && docker push $REPO/backend:manual
docker build --platform linux/amd64 -t $REPO/frontend:manual frontend && docker push $REPO/frontend:manual
BACKEND=$REPO/backend@$(gcloud artifacts docker images describe $REPO/backend:manual --format 'value(image_summary.digest)')
FRONTEND=$REPO/frontend@$(gcloud artifacts docker images describe $REPO/frontend:manual --format 'value(image_summary.digest)')
cd infra/gcp
terraform init -backend-config="bucket=$PROJECT-tfstate" -backend-config="prefix=frr/staging"
TF_VAR_sso_client_secret=… terraform apply -var-file=staging.tfvars \
  -var project_id=$PROJECT -var env=staging -var backend_image=$BACKEND -var frontend_image=$FRONTEND
gcloud run jobs execute frr-staging-migrate --region $REGION --wait
```

## Capacity and cost levers

| Variable | Default | Notes |
|---|---|---|
| `api_min_instances` / `api_max_instances` | 1 / 10 | Each instance runs `api_processes` uvicorn processes |
| `worker_min_instances` / `worker_max_instances` | 1 / 4 | At least one must run; each has `worker_concurrency` job slots |
| `db_tier` | `db-custom-2-8192` | Raise before raising instance counts |
| `db_high_availability` | true | Regional failover; recommended for prod |

**Connection budget:** each API process holds a pool of up to `DB_POOL_MAX` (8) connections;
each worker job slot holds two (work + heartbeat). Keep
`api instances × api_processes × 8 + worker instances × worker_concurrency × 2`
below `max_connections` (400) with headroom for migrations and admin. At the defaults'
maximum: `10 × 2 × 8 + 4 × 2 × 2 = 176`.

## Tear-down

Cloud SQL has deletion protection and the bucket refuses to delete while it holds objects.
Both are deliberate. To remove an environment, disable deletion protection on the instance,
empty the bucket, then `terraform destroy`.
