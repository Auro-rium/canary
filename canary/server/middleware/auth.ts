import type { Request, Response, NextFunction } from 'express';
import { config } from '../config.js';

export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  if (!header) {
    res.status(401).json({ error: 'Missing Authorization header' });
    return;
  }
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    res.status(401).json({ error: 'Invalid Authorization format — expected Bearer <token>' });
    return;
  }
  if (token !== config.API_SECRET_KEY) {
    res.status(403).json({ error: 'Invalid token' });
    return;
  }
  next();
}
