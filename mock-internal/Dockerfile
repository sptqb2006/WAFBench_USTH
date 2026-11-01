# mock-internal/Dockerfile
# Dockerfile for Mock Internal SSRF Target Service (Node.js 20 / Express)

FROM node:20-alpine

WORKDIR /app
RUN apk add --no-cache wget

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

EXPOSE 8080

CMD ["node", "server.js"]
