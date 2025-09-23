# Claude Code Slack Bot

A Slack bot that integrates with Claude Code SDK to provide AI-powered coding assistance directly in your Slack workspace.

## Features

- 🤖 Direct message support - chat with the bot privately
- 💬 Thread support - maintains conversation context within threads
- 🔄 Streaming responses - see Claude's responses as they're generated
- 📝 Markdown formatting - code blocks and formatting are preserved
- 🔧 Session management - maintains conversation context across messages
- ⚡ Real-time updates - messages update as Claude thinks

## Prerequisites

- Node.js 18+ installed
- A Slack workspace where you can install apps
- Claude Code

## Setup

### 1. Clone and Install

```bash
git clone <your-repo>
cd claude-code-slack
npm install
```

### 2. Create Slack App

#### Option A: Using App Manifest (Recommended)
1. Go to [api.slack.com/apps](https://api.slack.com/apps) and click "Create New App"
2. Choose "From an app manifest"
3. Select your workspace
4. Paste the contents of `slack-app-manifest.json` (or `slack-app-manifest.yaml`)
5. Review and create the app

#### Option B: Manual Configuration
1. Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app
2. Choose "From scratch" and give your app a name
3. Select the workspace where you want to install it

### 3. Configure Slack App

After creating the app (either method), you need to:

#### Generate Tokens
1. Go to "OAuth & Permissions" and install the app to your workspace
2. Copy the "Bot User OAuth Token" (starts with `xoxb-`)
3. Go to "Basic Information" → "App-Level Tokens"
4. Generate a token with `connections:write` scope
5. Copy the token (starts with `xapp-`)

#### Get Signing Secret
1. Go to "Basic Information"
2. Copy the "Signing Secret"

### 4. Configure Environment

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env`:
```env
# Slack App Configuration
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_APP_TOKEN=xapp-your-app-token
SLACK_SIGNING_SECRET=your-signing-secret

# Claude Code Configuration
# This is only needed if you don't use a Claude subscription
# ANTHROPIC_API_KEY=your-anthropic-api-key
# CLAUDE_CODE_USE_BEDROCK=1
# CLAUDE_CODE_USE_VERTEX=1

# GitHub App Integration (Optional - Recommended for GitHub access)
# GITHUB_APP_ID=123456
# GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nYour private key content here...\n-----END RSA PRIVATE KEY-----"
# GITHUB_INSTALLATION_ID=12345678

# GitHub Token Integration (Optional - Legacy fallback)
# GITHUB_TOKEN=ghp_your_personal_access_token

# Working Directory Configuration (Optional)
# BASE_DIRECTORY=/Users/username/Code/
```

### 5. Run the Bot

```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm run build
npm run prod
```

## Usage

### Setting Working Directory

Before using Claude Code, you must set a working directory. This tells Claude where your project files are located.

#### Set working directory:

**Relative paths** (if BASE_DIRECTORY is configured):
```
cwd project-name
```

**Absolute paths**:
```
cwd /path/to/your/project
```
or
```
set directory /path/to/your/project
```

#### Check current working directory:
```
cwd
```
or
```
get directory
```

### Working Directory Scope

- **Direct Messages**: Working directory is set for the entire conversation
- **Channels**: Working directory is set for the entire channel (prompted when bot joins)
- **Threads**: Can override the channel/DM directory for a specific thread by mentioning the bot

### Base Directory Configuration

You can configure a base directory in your `.env` file to use relative paths:

```env
BASE_DIRECTORY=/Users/username/Code/
```

With this set, you can use:
- `cwd herd-website` → resolves to `/Users/username/Code/herd-website`
- `cwd /absolute/path` → uses absolute path directly

### Direct Messages
Simply send a direct message to the bot with your request:
```
@ClaudeBot Can you help me write a Python function to calculate fibonacci numbers?
```

### In Channels
When you first add the bot to a channel, it will ask for a default working directory for that channel.

Mention the bot in any channel where it's been added:
```
@ClaudeBot Please review this code and suggest improvements
```

### Thread-Specific Working Directories
You can override the channel's default working directory for a specific thread:
```
@ClaudeBot cwd different-project
@ClaudeBot Now help me with this specific project
```

### Threads
Reply in a thread to maintain conversation context. The bot will remember previous messages in the thread.

### File Uploads
You can upload files and images directly to any conversation:

#### Supported File Types:
- **Images**: JPG, PNG, GIF, WebP, SVG
- **Text Files**: TXT, MD, JSON, JS, TS, PY, Java, etc.
- **Documents**: PDF, DOCX (limited support)
- **Code Files**: Most programming languages

#### Usage:
1. Upload a file by dragging and dropping or using the attachment button
2. Add optional text to describe what you want Claude to do with the file
3. Claude will analyze the file content and provide assistance

**Note**: Files are temporarily downloaded for processing and automatically cleaned up after analysis.

### MCP (Model Context Protocol) Servers

The bot supports MCP servers to extend Claude's capabilities with additional tools and resources.

#### Setup MCP Servers

1. **Create MCP configuration file:**
   ```bash
   cp mcp-servers.example.json mcp-servers.json
   ```

2. **Configure your servers** in `mcp-servers.json`:
   ```json
   {
     "mcpServers": {
       "filesystem": {
         "command": "npx",
         "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/files"]
       },
       "github": {
         "command": "npx", 
         "args": ["-y", "@modelcontextprotocol/server-github"],
         "env": {
           "GITHUB_TOKEN": "your-token"
         }
       }
     }
   }
   ```

#### MCP Commands

- **View configured servers**: `mcp` or `servers`
- **Reload configuration**: `mcp reload`

#### Available MCP Servers

- **Filesystem**: File system access (`@modelcontextprotocol/server-filesystem`)
- **GitHub**: GitHub API integration (`@modelcontextprotocol/server-github`)
- **PostgreSQL**: Database access (`@modelcontextprotocol/server-postgres`)
- **Web Search**: Search capabilities (custom servers)

All MCP tools are automatically allowed and follow the pattern: `mcp__serverName__toolName`

## Advanced Configuration

### GitHub Integration

The bot supports GitHub integration through the MCP GitHub server using **GitHub Apps** (recommended) or personal access tokens (legacy). This provides access to repositories, pull request management, and code analysis through Claude's MCP tools.

#### Setting up GitHub Integration with GitHub Apps (Recommended)

GitHub Apps provide better security and granular permissions compared to personal access tokens. They also provide higher rate limits and institutional identity.

1. **Create a GitHub App:**

   **Step-by-step instructions:**
   
   a. **Navigate to GitHub Settings:**
      - Go to [github.com](https://github.com) and sign in
      - Click your profile picture in the top right corner
      - Select "Settings" from the dropdown menu
   
   b. **Access Developer Settings:**
      - In the left sidebar, scroll down and click "Developer settings"
      - Click "GitHub Apps"
      - Click "New GitHub App"
   
   c. **Configure the GitHub App:**
      - **GitHub App name**: "Claude Code Slack Bot" (or your preferred name)
      - **Homepage URL**: Your organization's website or the repository URL
      - **Webhook URL**: Leave blank (not used for this integration)
      - **Webhook secret**: Leave blank
      - **Permissions**: Select the following repository permissions:
        - ✅ `Contents` - Read & Write (for reading and modifying files)
        - ✅ `Issues` - Read & Write (for issue management)
        - ✅ `Pull requests` - Read & Write (for PR management)
        - ✅ `Metadata` - Read (for basic repository information)
        - ✅ `Actions` - Read (optional, for viewing CI/CD status)
      - **Organization permissions** (optional):
        - ✅ `Members` - Read (for team information)
      - **User permissions**: None required
      - **Subscribe to events**: None required (we don't use webhooks)
      - **Where can this GitHub App be installed?**: Choose based on your needs
        - "Only on this account" for personal use
        - "Any account" if you plan to share the app
   
   d. **Create the App:**
      - Click "Create GitHub App"
      - You'll be redirected to the app's settings page
   
   e. **Generate Private Key:**
      - Scroll down to "Private keys" section
      - Click "Generate a private key"
      - Download the `.pem` file and store it securely
   
   f. **Note the App ID:**
      - At the top of the app settings page, note the "App ID" (e.g., 123456)

2. **Install the GitHub App:**

   a. **Install on Repositories:**
      - Go to the "Install App" tab in your GitHub App settings
      - Click "Install" next to your account/organization
      - Choose "All repositories" or "Selected repositories" based on your needs
      - Complete the installation
   
   b. **Note the Installation ID:**
      - After installation, you'll see the installation URL
      - The Installation ID is in the URL: `https://github.com/settings/installations/12345678`
      - Note this number (e.g., 12345678)

3. **Configure Environment Variables:**
   ```env
   # GitHub App Configuration (Recommended)
   GITHUB_APP_ID=123456
   GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
   MIIEpAIBAAKCAQEA...
   (your private key content here)
   ...
   -----END RSA PRIVATE KEY-----"
   GITHUB_INSTALLATION_ID=12345678
   ```

   **Important Notes:**
   - The private key should include the full PEM format with line breaks
   - Store the private key securely and never commit it to version control
   - The bot will automatically discover installations if INSTALLATION_ID is not set

#### Legacy Setup with Personal Access Tokens (Fallback)

If you prefer or need to use personal access tokens instead of GitHub Apps:

1. **Create a Personal Access Token:**
   
   **Step-by-step instructions:**
   
   a. **Navigate to GitHub Settings:**
      - Go to [github.com](https://github.com) and sign in
      - Click your profile picture in the top right corner
      - Select "Settings" from the dropdown menu
   
   b. **Access Developer Settings:**
      - In the left sidebar, scroll down and click "Developer settings"
      - Click "Personal access tokens"
      - Select "Tokens (classic)"
   
   c. **Generate New Token:**
      - Click "Generate new token (classic)"
      - You may be prompted to confirm your password
   
   d. **Configure Token:**
      - **Note**: Give it a descriptive name like "Claude Code Slack Bot"
      - **Expiration**: Choose an appropriate expiration (90 days, 1 year, or no expiration)
      - **Select scopes** based on your needs:
        - ✅ `repo` - Full control of private repositories (includes all repo permissions)
        - ✅ `read:org` - Read organization membership and team membership
        - ✅ `read:user` - Read user profile data
        - ✅ `user:email` - Access user email addresses (read-only)
   
   e. **Generate and Save Token:**
      - Click "Generate token" at the bottom
      - **Important**: Copy the token immediately - you won't be able to see it again
      - Store it securely (password manager, secure notes, etc.)
   
   **Token Format**: The token will look like `ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

   **Security Notes:**
   - Treat this token like a password - never share it publicly
   - Don't commit it to version control
   - Use environment variables or secure secret management
   - Consider setting an expiration date for better security
   - You can regenerate the token anytime if compromised

   **Permission Explanation:**
   - `repo`: Grants full access to repositories (read, write, admin)
   - `read:org`: Allows reading organization membership and team membership
   - `read:user`: Allows reading basic user profile information
   - `user:email`: Allows reading user email addresses

2. **Configure Environment Variables:**
   ```env
   # GitHub Token for MCP (Legacy fallback)
   GITHUB_TOKEN=ghp_your_personal_access_token
   ```

#### Authentication Priority

The bot will automatically use GitHub App authentication when configured, and fall back to personal access tokens if GitHub App settings are not available.

#### Advantages of GitHub Apps over Personal Tokens
- **Better Security**: Apps have granular permissions instead of broad user-level access
- **Institutional Identity**: Actions appear as the app, not a personal user
- **No User Dependency**: Doesn't depend on a specific user's account remaining active
- **Audit Trail**: Better tracking of automated actions
- **Rate Limits**: Higher rate limits for API requests
- **Revocable**: Easy to revoke access without affecting user's personal tokens

3. **Configure MCP Server:**
   The Docker container includes a pre-configured `mcp-servers.json` file that automatically sets up:
   - **Filesystem server**: Provides access to the `/usercontent` directory
   - **GitHub server**: Uses GitHub App authentication when configured, or falls back to `GITHUB_TOKEN`
   
   No additional MCP configuration is needed for Docker deployment. The bot will automatically use GitHub App authentication when available.

### Using AWS Bedrock
Set these environment variables:
```env
CLAUDE_CODE_USE_BEDROCK=1
# AWS credentials should be configured via AWS CLI or IAM roles
```

### Using Google Vertex AI
Set these environment variables:
```env
CLAUDE_CODE_USE_VERTEX=1
# Google Cloud credentials should be configured
```

## Development

### Debug Mode

Enable debug logging by setting `DEBUG=true` in your `.env` file:
```env
DEBUG=true
```

This will show detailed logs including:
- Incoming Slack messages
- Claude SDK request/response details
- Session management operations
- Message streaming updates

### Project Structure
```
src/
├── index.ts          # Application entry point
├── config.ts         # Configuration management
├── types.ts                      # TypeScript type definitions
├── claude-handler.ts             # Claude Code SDK integration
├── slack-handler.ts              # Slack event handling
├── working-directory-manager.ts  # Working directory management
└── logger.ts                     # Logging utility
```

### Available Scripts
- `npm run dev` - Start in development mode with hot reload
- `npm run build` - Build TypeScript to JavaScript
- `npm start` - Run the compiled JavaScript
- `npm run prod` - Run production build

## Troubleshooting

### Bot not responding
1. Check that the bot is running (`npm run dev`)
2. Verify all environment variables are set correctly
3. Ensure the bot has been invited to the channel
4. Check Slack app permissions are configured correctly

### Authentication errors
1. Verify your Anthropic API key is valid
2. Check Slack tokens haven't expired
3. Ensure Socket Mode is enabled

### Message formatting issues
The bot converts Claude's markdown to Slack's formatting. Some complex formatting may not translate perfectly.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT