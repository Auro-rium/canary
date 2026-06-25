function require_env(key: string, fallback?: string): string {
  const val = process.env[key] ?? fallback;
  if (!val) throw new Error(`Missing required env var: ${key}`);
  return val;
}

export const config = {
  API_SECRET_KEY: require_env('API_SECRET_KEY'),
  AWS_REGION: process.env.AWS_REGION ?? 'us-east-1',
  BEDROCK_MODEL_ID: process.env.BEDROCK_MODEL_ID ?? 'anthropic.claude-3-5-sonnet-20241022-v2:0',
  DOWNSTREAM_URL: process.env.DOWNSTREAM_URL ?? 'http://localhost:9000',
  PORT: parseInt(process.env.PORT ?? '8000', 10),
};
