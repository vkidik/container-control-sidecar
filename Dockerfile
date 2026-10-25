FROM node:24.12.0-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=node:node src ./src
RUN mkdir -p /data /agent-data && chown node:node /data /agent-data
USER node

FROM runtime AS sidecar
ARG CONTROL_PLANE_URL
RUN node -e "const u=new URL(process.argv[1]); if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash) throw new Error('CONTROL_PLANE_URL must be a clean https URL')" "$CONTROL_PLANE_URL"
ENV CONTROL_PLANE_URL=$CONTROL_PLANE_URL
CMD ["node", "src/control-plane/main.js"]
