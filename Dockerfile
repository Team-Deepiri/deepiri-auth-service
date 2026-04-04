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
COPY backend/deepiri-auth-service/.npmrc ./

# Copy Prisma schema before npm install (needed for postinstall script)
COPY backend/deepiri-auth-service/prisma ./prisma

RUN npm ci --legacy-peer-deps && npm cache clean --force

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
