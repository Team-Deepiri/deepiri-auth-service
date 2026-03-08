FROM node:18-slim AS shared-utils-builder
WORKDIR /shared-utils
COPY platform-services/shared/deepiri-shared-utils/package.json ./
COPY platform-services/shared/deepiri-shared-utils/tsconfig.json ./
COPY platform-services/shared/deepiri-shared-utils/src ./src
RUN npm install --legacy-peer-deps && npm run build

# Build the service
FROM node:18-slim

WORKDIR /app

RUN apt-get update && apt-get install -y openssl ca-certificates curl dumb-init bash && rm -rf /var/lib/apt/lists/*

# Copy K8s env loader scripts
COPY --chown=root:root platform-services/shared/scripts/load-k8s-env.sh /usr/local/bin/load-k8s-env.sh
COPY --chown=root:root platform-services/shared/scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY --chown=root:root platform-services/shared/scripts/prisma-baseline.sh /usr/local/bin/prisma-baseline.sh
RUN chmod +x /usr/local/bin/load-k8s-env.sh /usr/local/bin/docker-entrypoint.sh /usr/local/bin/prisma-baseline.sh

COPY platform-services/backend/deepiri-auth-service/package.json ./
COPY platform-services/backend/deepiri-auth-service/tsconfig.json ./

# Copy Prisma schema before npm install (needed for postinstall script)
COPY platform-services/backend/deepiri-auth-service/prisma ./prisma

RUN node -e "const fs=require('fs');const p=JSON.parse(fs.readFileSync('package.json','utf8'));delete p.dependencies['@deepiri/shared-utils'];fs.writeFileSync('package.json',JSON.stringify(p,null,2))"

RUN npm install --legacy-peer-deps && npm cache clean --force

COPY --from=shared-utils-builder /shared-utils/package.json /app/node_modules/@deepiri/shared-utils/package.json
COPY --from=shared-utils-builder /shared-utils/dist /app/node_modules/@deepiri/shared-utils/dist

# Copy source files
COPY platform-services/backend/deepiri-auth-service/src ./src

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
