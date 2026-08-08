# AWS hosted deployment

The hosted Canary control plane is split into two ECS Fargate services using
the same `cyber-redteam-foundry` image:

* `canary-api` runs FastAPI behind an HTTPS Application Load Balancer.
* `canary-worker` runs the RQ worker and owns release execution after the API
  has committed the release row.

Persistent services are RDS PostgreSQL (`DATABASE_URL`) and ElastiCache Redis
(`REDIS_URL`). Store both values in AWS Secrets Manager or SSM Parameter Store;
do not put credentials in task definitions, Git, or Vercel environment
variables. The ECS task role should grant only the configured Bedrock model
invocation and read access to those specific secrets. CloudWatch receives
container logs. Keep the ALB and data services in private subnets according
to the deployment's network policy.

## Deployment order

1. Build and push `cyber-redteam-foundry/Dockerfile` to ECR.
2. Provision RDS PostgreSQL, ElastiCache Redis, ECS cluster, task execution
   role, task role, security groups, and the HTTPS ALB.
3. Run `migrations/001_cutc_release_domain.sql` against the RDS database using
   the deployment migration job or an approved migration runner. The API and
   worker do not perform additive PostgreSQL column migrations on startup;
   schema changes belong in this migration path.
4. Render the task definition templates in this directory with the real ECR
   image and secret ARNs, then register one API task definition and one worker
   task definition.
5. Deploy the API service with `RELEASE_EXECUTION_MODE=rq` and the worker
   service with the same `DATABASE_URL`, `REDIS_URL`, `RELEASE_QUEUE_NAME`,
   Bedrock region, and authentication configuration.
6. Configure the ALB health check to `GET /health` and set
   `FRONTEND_ORIGINS` to the Vercel dashboard origin.

For local development, leave `RELEASE_EXECUTION_MODE=thread` and use the
existing SQLite path. The same image can still run the optional local Redis
worker from `docker-compose.yml`.

## Operational invariants

* The API enqueues only after the release transaction commits.
* RQ job IDs are deterministic per release, so duplicate delivery is safe at
  the release execution boundary.
* Retries are bounded by `MAX_RETRIES`/`RELEASE_JOB_TIMEOUT_SECONDS` and final
  failures are persisted as release failures.
* Scale API and worker services independently; set the worker service's
  desired count and RQ concurrency to the approved campaign limit.
* Apply network egress controls in addition to application-level target URL
  validation. Canary should reach only explicitly verified targets.

The JSON files are templates, not ready-to-register production definitions:
replace `${...}` placeholders during deployment and keep secret values in
Secrets Manager.
