FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN mkdir -p /app/data /tmp/exports /app/public/uploads/avatars

EXPOSE 3000

CMD ["node", "clean/src/app.js"]
