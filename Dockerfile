FROM node:20-slim

WORKDIR /app

COPY package*.json ./
COPY node_modules ./node_modules
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
