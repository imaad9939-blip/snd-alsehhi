FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
RUN mkdir -p /app/data /app/private_uploads && chown -R node:node /app
USER node
ENV NODE_ENV=production PORT=3000 HOST=0.0.0.0 COOKIE_SECURE=true
EXPOSE 3000
CMD ["node", "server.js"]
