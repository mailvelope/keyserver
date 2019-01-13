FROM node:latest
WORKDIR /app
COPY . /app
RUN npm install \
    && curl -L https://github.com/Yelp/dumb-init/releases/download/v1.2.2/dumb-init_1.2.2_amd64 -o /app/dumb-init \
    && chmod +x /app/dumb-init


ENTRYPOINT ["/usr/local/bin/dumb-init", "--"]
CMD [ "npm", "start" ]




