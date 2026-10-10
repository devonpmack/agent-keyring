# syntax=docker/dockerfile:1
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci

# Local development (docker compose): source mounted, tsx watch.
FROM deps AS dev
COPY . .
CMD ["npx", "tsx", "watch", "src/main.ts"]

FROM deps AS build
COPY . .
RUN npm run build

FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
COPY static ./static
USER node
EXPOSE 8080
CMD ["node", "dist/main.js"]
