FROM node:20-alpine

WORKDIR /app
RUN apk add --no-cache wget

COPY package.json ./
RUN npm install --production

COPY server.js ./

EXPOSE 8080

CMD ["node", "server.js"]
