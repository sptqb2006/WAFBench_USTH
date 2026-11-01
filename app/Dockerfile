# app/Dockerfile
# Dockerfile for Vulnerable Target Application (Node.js 20 / Express)

FROM node:20-alpine

WORKDIR /app

# Cai dat curl / wget de ho tro healthcheck
RUN apk add --no-cache wget curl

COPY package.json ./
RUN npm install --omit=dev

COPY src/ ./src/
COPY public/ ./public/

EXPOSE 3000

CMD ["node", "src/server.js"]
