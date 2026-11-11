# G9 frontend — Vite build served via nginx, loopback-only.
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
# --network=host: the registry fetch uses the host's working resolver
# directly (the daemon's embedded DNS can fail on systemd-resolved hosts).
RUN --network=host npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
