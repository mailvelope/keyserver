FROM node:latest

WORKDIR /app
ADD . .
RUN npm install

ENTRYPOINT ["node"]
CMD [ "index.js" ]