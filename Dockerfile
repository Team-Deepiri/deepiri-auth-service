# Build shared-utils first
FROM node:18-slim AS shared-utils-builder
WORKDIR /shared-utils
COPY shared/deepiri-shared-utils/package.json ./
COPY shared/deepiri-shared-utils/tsconfig.json ./
COPY shared/deepiri-shared-utils/src ./src
# Add retry logic for network issues
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm config set fetch-timeout 300000 && \
    npm install --legacy-peer-deps || \
    (sleep 10 && npm install --legacy-peer-deps) || \
    (sleep 20 && npm install --legacy-peer-deps) && \
    npm run build

# Build the service
FROM node:18-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssl ca-certificates curl dumb-init bash && rm -rf /var/lib/apt/lists/*

# Copy K8s env loader scripts
COPY --chown=root:root shared/scripts/load-k8s-env.sh /usr/local/bin/load-k8s-env.sh
COPY --chown=root:root shared/scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chown=root:root shared/scripts/prisma-baseline.sh /usr/local/bin/prisma-baseline.sh
RUN chmod +x /usr/local/bin/load-k8s-env.sh /usr/local/bin/docker-entrypoint.sh /usr/local/bin/prisma-baseline.sh

# Copy package files (avoid copying lockfile here to prevent stale local paths)
COPY backend/deepiri-auth-service/package.json ./
COPY backend/deepiri-auth-service/tsconfig.json ./

# Copy Prisma schema before npm install (needed for postinstall script)
COPY backend/deepiri-auth-service/prisma ./prisma

# Copy built shared-utils to a temp location
COPY --from=shared-utils-builder /shared-utils /shared-utils

# Install shared-utils as a local file dependency first, then install other dependencies
# Add retry logic for network issues
RUN npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm config set fetch-timeout 300000 && \
    npm install --legacy-peer-deps file:/shared-utils || \
    (sleep 10 && npm install --legacy-peer-deps file:/shared-utils) || \
    (sleep 20 && npm install --legacy-peer-deps file:/shared-utils) && \
    npm install --legacy-peer-deps || \
    (sleep 10 && npm install --legacy-peer-deps) || \
    (sleep 20 && npm install --legacy-peer-deps) && \
    npm cache clean --force

# Copy source files
COPY backend/deepiri-auth-service/src ./src

# Prisma generate is already run by postinstall script, but ensure it's done
RUN npx prisma generate || true

# Build TypeScript
RUN npm run build

# Create non-root user and set up directories
RUN groupadd -r nodejs -g 1001 && \
    useradd -r -u 1001 -g nodejs nodejs && \
    mkdir -p logs && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]
