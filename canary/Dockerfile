# ── Stage 1: Build React app ─────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Install deps first (better layer cache)
COPY package.json package-lock.json ./
RUN npm ci

# Build args baked into the JS bundle at build time
ARG VITE_API_URL=""
ARG VITE_API_TOKEN=""
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_API_TOKEN=$VITE_API_TOKEN

COPY . .
RUN npm run build

# ── Stage 2: Serve via nginx ──────────────────────────────────────────────────
FROM nginx:1.25-alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
