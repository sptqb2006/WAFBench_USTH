FROM node:20-alpine

WORKDIR /app

# Install curl / wget for container healthchecks
RUN apk add --no-cache wget curl

COPY package.json ./
RUN npm install --production

COPY src/ ./src/
COPY public/ ./public/

EXPOSE 3000

CMD ["node", "src/server.js"]
