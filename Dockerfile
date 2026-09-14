# Stage 1: Build dependencies
FROM node:20-slim AS builder

WORKDIR /usr/src/app

# Copy dependency manifests
COPY package*.json ./

# Install all dependencies
RUN npm ci

# Copy backend source files
COPY . .

# Prune devDependencies to keep the image slim
RUN npm prune --production

# Stage 2: Clean runtime image
FROM node:20-slim

WORKDIR /usr/src/app

# Copy files from the builder stage
COPY --from=builder /usr/src/app ./

# Create uploads directory and ensure node user has permissions
RUN mkdir -p uploads && chown -R node:node uploads

# Configure default port and node environment
ENV NODE_ENV=production
ENV PORT=8080

# Run container process as a secure, non-root user
USER node

# Expose server port
EXPOSE 8080

# Start application server
CMD ["node", "src/server.js"]
