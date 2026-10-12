FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY server.js index.html ./
EXPOSE 3050
ENV PORT=3050
CMD ["node", "server.js"]
