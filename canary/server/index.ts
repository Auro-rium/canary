import express from 'express';
import { requireAuth } from './middleware/auth.js';
import { router } from './routes/api.js';
import { config } from './config.js';

const app = express();

app.use(express.json());

// CORS for local dev
app.use((_req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (_req.method === 'OPTIONS') { res.sendStatus(204); return; }
  next();
});

// All routes require auth
app.use(requireAuth);

// Mount API routes
app.use('/api', router);

app.listen(config.PORT, () => {
  console.log(`Agent Canary BFF listening on port ${config.PORT}`);
  console.log(`Bedrock model: ${config.BEDROCK_MODEL_ID} (${config.AWS_REGION})`);
  console.log(`Downstream: ${config.DOWNSTREAM_URL}`);
});
