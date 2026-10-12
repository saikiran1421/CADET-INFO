FROM node:22-slim
WORKDIR /app
COPY . .
# Runs as root so it can write to the platform-mounted /data disk (Render mounts it root-owned).
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
