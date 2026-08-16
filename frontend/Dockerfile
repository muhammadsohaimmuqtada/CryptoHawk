FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY --chown=nginx:nginx --from=build /app/dist /usr/share/nginx/html
USER nginx
ENTRYPOINT []
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
