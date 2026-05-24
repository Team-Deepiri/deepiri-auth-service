FROM ghcr.io/team-deepiri/deepiri-suite:18-slim

COPY shared/deepiri-shared-utils/package*.json /shared/deepiri-shared-utils/
COPY shared/deepiri-shared-utils/tsconfig.json /shared/deepiri-shared-utils/
COPY shared/deepiri-shared-utils/src /shared/deepiri-shared-utils/src
COPY backend/deepiri-auth-service/package*.json ./
COPY backend/deepiri-auth-service/tsconfig.json ./
COPY backend/deepiri-auth-service/prisma ./prisma

# Install dependencies and build shared local modules first
RUN node -e "const fs=require('fs'),lock=JSON.parse(fs.readFileSync('package-lock.json'));delete lock.packages['../../shared/deepiri-shared-utils'];delete lock.packages['node_modules/@team-deepiri/shared-utils'];fs.writeFileSync('package-lock.json',JSON.stringify(lock));" \
 && cd /shared/deepiri-shared-utils \
 && npm ci --legacy-peer-deps \
 && npx tsc \
 && node -e "const fs=require('fs'),p=JSON.parse(fs.readFileSync('package.json'));delete p.scripts.prepare;fs.writeFileSync('package.json',JSON.stringify(p,null,2));" \
 && cd /app \
 && npm install --legacy-peer-deps \
 && npm install --legacy-peer-deps file:/shared/deepiri-shared-utils \
 && cd /shared/deepiri-shared-utils \
 && npm ci --omit=dev --legacy-peer-deps \
 && cd /app \
 && npm cache clean --force

# Copy source files
COPY backend/deepiri-auth-service/src ./src

# Generate Prisma client and compile the application cleanly
RUN npx prisma generate || true \
 && npm run build

RUN mkdir -p logs && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]