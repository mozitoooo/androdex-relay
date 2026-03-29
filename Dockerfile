FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

ENV NODE_ENV=production
ENV PORT=9000
ENV HOST=0.0.0.0

EXPOSE 9000

CMD ["node", "server.js"]
