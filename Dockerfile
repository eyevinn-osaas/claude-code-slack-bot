# Use Node.js LTS version
FROM node:18-alpine

# Install system dependencies including bash and common shell utilities
RUN apk add --no-cache git curl bash coreutils findutils grep sed github-cli openssl

# Install ripgrep (required by Claude Code SDK)
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/14.1.1/ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz && \
    tar xf ripgrep-14.1.1-x86_64-unknown-linux-musl.tar.gz && \
    mv ripgrep-14.1.1-x86_64-unknown-linux-musl/rg /usr/local/bin/ && \
    rm -rf ripgrep-14.1.1-*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Install tsx globally
RUN npm install -g tsx

# Install MCP servers globally for GitHub app integration
RUN npm install -g @modelcontextprotocol/server-filesystem@latest
RUN npm install -g @modelcontextprotocol/server-github@latest  

# Copy source code
COPY . .

# Copy Claude Code settings to home directory for default permissions
COPY claude-code-settings.json /home/nodejs/.claude/settings.json

# Copy and make the setup script executable
COPY setup-git-auth.sh /usr/local/bin/setup-git-auth.sh
RUN chmod +x /usr/local/bin/setup-git-auth.sh

# Create the user content directory
RUN mkdir -p /usercontent

# Create non-root user with bash shell
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001 -s /bin/bash

# Change ownership of directories
RUN chown -R nodejs:nodejs /app
RUN chown -R nodejs:nodejs /usercontent
RUN chown -R nodejs:nodejs /home/nodejs/.claude
RUN chown nodejs:nodejs /home/nodejs/.claude/settings.json

# Set environment variable for base directory
ENV BASE_DIRECTORY=/usercontent

USER nodejs

# Configure Git to use token-based authentication for GitHub
# This will be set up at runtime when GITHUB_TOKEN is available

# Expose the port
EXPOSE $PORT

# Start both the healthcheck server and the main application
CMD ["/bin/bash", "-c", "source /usr/local/bin/setup-git-auth.sh && node healthcheck.js & npm run start"]