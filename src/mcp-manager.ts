import * as fs from 'fs';
import * as path from 'path';
import { Logger } from './logger';
import { getGitHubAppAuth, isGitHubAppConfigured } from './github-auth.js';

export type McpStdioServerConfig = {
  type?: 'stdio'; // Optional for backwards compatibility
  command: string;
  args?: string[];
  env?: Record<string, string>;
};

export type McpSSEServerConfig = {
  type: 'sse';
  url: string;
  headers?: Record<string, string>;
};

export type McpHttpServerConfig = {
  type: 'http';
  url: string;
  headers?: Record<string, string>;
};

export type McpServerConfig = McpStdioServerConfig | McpSSEServerConfig | McpHttpServerConfig;

export interface McpConfiguration {
  mcpServers: Record<string, McpServerConfig>;
}

export class McpManager {
  private logger = new Logger('McpManager');
  private config: McpConfiguration | null = null;
  private configPath: string;

  constructor(configPath: string = './mcp-servers.json') {
    this.configPath = path.resolve(configPath);
  }

  loadConfiguration(): McpConfiguration | null {
    if (this.config) {
      return this.config;
    }

    try {
      if (!fs.existsSync(this.configPath)) {
        this.logger.info('No MCP configuration file found', { path: this.configPath });
        return null;
      }

      const configContent = fs.readFileSync(this.configPath, 'utf-8');
      const parsedConfig = JSON.parse(configContent);

      if (!parsedConfig.mcpServers || typeof parsedConfig.mcpServers !== 'object') {
        this.logger.warn('Invalid MCP configuration: missing or invalid mcpServers', { path: this.configPath });
        return null;
      }

      // Validate server configurations
      for (const [serverName, serverConfig] of Object.entries(parsedConfig.mcpServers)) {
        if (!this.validateServerConfig(serverName, serverConfig as McpServerConfig)) {
          this.logger.warn('Invalid server configuration, skipping', { serverName });
          delete parsedConfig.mcpServers[serverName];
        }
      }

      this.config = parsedConfig as McpConfiguration;
      
      this.logger.info('Loaded MCP configuration', {
        path: this.configPath,
        serverCount: Object.keys(this.config.mcpServers).length,
        servers: Object.keys(this.config.mcpServers),
      });

      return this.config;
    } catch (error) {
      this.logger.error('Failed to load MCP configuration', error);
      return null;
    }
  }

  private validateServerConfig(serverName: string, config: McpServerConfig): boolean {
    if (!config || typeof config !== 'object') {
      return false;
    }

    // Validate based on type
    if (!config.type || config.type === 'stdio') {
      // Stdio server
      const stdioConfig = config as McpStdioServerConfig;
      if (!stdioConfig.command || typeof stdioConfig.command !== 'string') {
        this.logger.warn('Stdio server missing command', { serverName });
        return false;
      }
    } else if (config.type === 'sse' || config.type === 'http') {
      // SSE or HTTP server
      const urlConfig = config as McpSSEServerConfig | McpHttpServerConfig;
      if (!urlConfig.url || typeof urlConfig.url !== 'string') {
        this.logger.warn('SSE/HTTP server missing URL', { serverName, type: config.type });
        return false;
      }
    } else {
      this.logger.warn('Unknown server type', { serverName, type: config.type });
      return false;
    }

    return true;
  }

  async getServerConfiguration(): Promise<Record<string, McpServerConfig> | undefined> {
    const baseDirectory = process.env.BASE_DIRECTORY || '/usercontent';
    const processedServers: Record<string, McpServerConfig> = {};

    // Load configuration from file if it exists
    const config = this.loadConfiguration();
    if (config) {
      // Process existing configuration servers
      for (const [serverName, serverConfig] of Object.entries(config.mcpServers)) {
        if (serverName === 'github' && isGitHubAppConfigured()) {
          // Replace GitHub token authentication with GitHub App authentication
          const githubAuth = getGitHubAppAuth();
          if (githubAuth) {
            try {
              const token = await githubAuth.getInstallationToken();
              const updatedConfig = { ...serverConfig };
              
              if (updatedConfig.type === 'stdio' || !updatedConfig.type) {
                const stdioConfig = updatedConfig as McpStdioServerConfig;
                stdioConfig.env = {
                  ...stdioConfig.env,
                  GITHUB_PERSONAL_ACCESS_TOKEN: token,
                };
              }
              
              processedServers[serverName] = updatedConfig;
              this.logger.info('Updated GitHub MCP server to use GitHub App authentication');
            } catch (error) {
              this.logger.error('Failed to get GitHub App token for MCP server:', error);
              // Fall back to original configuration
              processedServers[serverName] = serverConfig;
            }
          } else {
            processedServers[serverName] = serverConfig;
          }
        } else {
          processedServers[serverName] = serverConfig;
        }
      }
    }

    // Always add core MCP servers programmatically for GitHub App integration
    if (isGitHubAppConfigured()) {
      const githubAuth = getGitHubAppAuth();
      if (githubAuth) {
        try {
          const token = await githubAuth.getInstallationToken();
          
          // Add filesystem server if not already configured
          if (!processedServers.filesystem) {
            processedServers.filesystem = {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-filesystem', baseDirectory]
            };
          }

          // Add GitHub server if not already configured
          if (!processedServers.github) {
            processedServers.github = {
              command: 'npx',
              args: ['-y', '@modelcontextprotocol/server-github'],
              env: {
                GITHUB_PERSONAL_ACCESS_TOKEN: token
              }
            };
          }

          this.logger.info('Added GitHub App-authenticated MCP servers', {
            servers: Object.keys(processedServers),
            baseDirectory
          });
        } catch (error) {
          this.logger.error('Failed to configure GitHub App MCP servers:', error);
        }
      }
    } else if (process.env.GITHUB_TOKEN) {
      // Fallback to GitHub token authentication
      const githubToken = process.env.GITHUB_TOKEN;
      
      // Add filesystem server if not already configured
      if (!processedServers.filesystem) {
        processedServers.filesystem = {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', baseDirectory]
        };
      }

      // Add GitHub server if not already configured
      if (!processedServers.github) {
        processedServers.github = {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-github'],
          env: {
            GITHUB_PERSONAL_ACCESS_TOKEN: githubToken
          }
        };
      }

      this.logger.info('Added GitHub token-authenticated MCP servers', {
        servers: Object.keys(processedServers),
        baseDirectory
      });
    } else {
      // Add minimal filesystem server if no GitHub authentication is available
      if (!processedServers.filesystem) {
        processedServers.filesystem = {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', baseDirectory]
        };
        this.logger.info('Added filesystem MCP server (no GitHub authentication available)');
      }
    }

    return Object.keys(processedServers).length > 0 ? processedServers : undefined;
  }

  getDefaultAllowedTools(): string[] {
    // Get all server names from both configuration file and programmatically added servers
    const serverNames = new Set<string>();
    
    // Add servers from configuration file
    const config = this.loadConfiguration();
    if (config) {
      Object.keys(config.mcpServers).forEach(name => serverNames.add(name));
    }

    // Add programmatically added servers based on GitHub configuration
    if (isGitHubAppConfigured() || process.env.GITHUB_TOKEN) {
      serverNames.add('filesystem');
      serverNames.add('github');
    } else {
      serverNames.add('filesystem');
    }

    // Allow all tools from all servers by default
    return Array.from(serverNames).map(serverName => `mcp__${serverName}`);
  }

  async formatMcpInfo(): Promise<string> {
    // Get all configured servers (both from file and programmatically added)
    const allServers = await this.getServerConfiguration();
    
    if (!allServers || Object.keys(allServers).length === 0) {
      return 'No MCP servers configured.';
    }

    let info = '🔧 **MCP Servers Configured:**\n\n';
    
    for (const [serverName, serverConfig] of Object.entries(allServers)) {
      const type = serverConfig.type || 'stdio';
      
      // Add authentication indicator for GitHub servers
      let authInfo = '';
      if (serverName === 'github' || serverName === 'git') {
        if (isGitHubAppConfigured()) {
          authInfo = ' (GitHub App)';
        } else if (process.env.GITHUB_TOKEN) {
          authInfo = ' (Token)';
        }
      }
      
      info += `• **${serverName}** (${type}${authInfo})\n`;
      
      if (type === 'stdio') {
        const stdioConfig = serverConfig as McpStdioServerConfig;
        info += `  Command: \`${stdioConfig.command}\`\n`;
        if (stdioConfig.args && stdioConfig.args.length > 0) {
          info += `  Args: \`${stdioConfig.args.join(' ')}\`\n`;
        }
      } else {
        const urlConfig = serverConfig as McpSSEServerConfig | McpHttpServerConfig;
        info += `  URL: \`${urlConfig.url}\`\n`;
      }
      info += '\n';
    }

    info += 'Available tools follow the pattern: `mcp__serverName__toolName`\n';
    info += 'All MCP tools are allowed by default.';

    return info;
  }

  reloadConfiguration(): McpConfiguration | null {
    this.config = null;
    return this.loadConfiguration();
  }
}