FROM ghcr.io/team-deepiri/deepiri-base:18-slim

COPY backend/deepiri-auth-service/package*.json ./
COPY backend/deepiri-auth-service/tsconfig.json ./

# Copy Prisma schema before npm install (needed for postinstall script)
COPY backend/deepiri-auth-service/prisma ./prisma

RUN --mount=type=secret,id=github_token \
    { echo "@team-deepiri:registry=https://npm.pkg.github.com"; \
      echo "//npm.pkg.github.com/:_authToken=$(cat /run/secrets/github_token)"; \
    } > .npmrc \
 && npm ci --legacy-peer-deps \
 && npm cache clean --force \
 && echo "@team-deepiri:registry=https://npm.pkg.github.com" > .npmrc

# Copy source files
COPY backend/deepiri-auth-service/src ./src

# Prisma generate is already run by postinstall script, but ensure it's done
RUN npx prisma generate || true

# Build TypeScript
RUN npm run build

RUN mkdir -p logs && chown -R nodejs:nodejs /app

USER nodejs

EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/bin/dumb-init", "--", "node", "dist/server.js"]
