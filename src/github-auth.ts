import jwt from 'jsonwebtoken';
import { config } from './config.js';
import { Logger } from './logger.js';

const logger = new Logger('GitHubAuth');

export interface GitHubAppConfig {
  appId: string;
  privateKey: string;
  installationId?: string;
}

export class GitHubAppAuth {
  private installationId?: number;
  private installationTokenCache: {
    token: string;
    expiresAt: Date;
  } | null = null;

  constructor(private appConfig: GitHubAppConfig) {
    if (appConfig.installationId) {
      this.installationId = parseInt(appConfig.installationId, 10);
    }
  }

  async getInstallationToken(installationId?: number): Promise<string> {
    const targetInstallationId = installationId || this.installationId;
    
    if (!targetInstallationId) {
      throw new Error('Installation ID is required. Either provide it as parameter or configure it in environment variables.');
    }

    if (this.installationTokenCache && this.installationTokenCache.expiresAt > new Date()) {
      logger.info('Using cached GitHub App installation token');
      return this.installationTokenCache.token;
    }

    try {
      logger.info(`Generating GitHub App installation token for installation ${targetInstallationId}`);
      
      // Get a fresh installation token directly using the GitHub API
      const appJWT = await this.getAppJWT();
      const response = await fetch(`https://api.github.com/app/installations/${targetInstallationId}/access_tokens`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${appJWT}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Claude-Code-Slack-Bot/1.0.0',
        },
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const tokenData = await response.json() as { token: string; expires_at: string };
      const expiresAt = new Date(tokenData.expires_at);
      
      this.installationTokenCache = {
        token: tokenData.token,
        expiresAt,
      };

      logger.info(`GitHub App installation token generated, expires at ${expiresAt.toISOString()}`);
      return tokenData.token;
    } catch (error) {
      logger.error('Failed to generate GitHub App installation token:', error);
      throw new Error(`Failed to authenticate with GitHub App: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async getAppJWT(): Promise<string> {
    try {
      const now = Math.floor(Date.now() / 1000);
      const payload = {
        iat: now - 60,
        exp: now + (10 * 60),
        iss: this.appConfig.appId,
      };

      return jwt.sign(payload, this.appConfig.privateKey, { algorithm: 'RS256' });
    } catch (error) {
      logger.error('Failed to generate GitHub App JWT:', error);
      throw new Error(`Failed to generate GitHub App JWT: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  async listInstallations(): Promise<Array<{ id: number; account: { login: string; type: string } }>> {
    try {
      logger.info('Fetching GitHub App installations');
      
      const appJWT = await this.getAppJWT();
      const response = await fetch('https://api.github.com/app/installations', {
        headers: {
          'Authorization': `Bearer ${appJWT}`,
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'Claude-Code-Slack-Bot/1.0.0',
        },
      });

      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const installations = await response.json() as Array<{
        id: number;
        account: { login: string; type: string };
      }>;
      logger.info(`Found ${installations.length} GitHub App installations`);
      
      return installations.map((installation) => ({
        id: installation.id,
        account: {
          login: installation.account.login,
          type: installation.account.type,
        },
      }));
    } catch (error) {
      logger.error('Failed to list GitHub App installations:', error);
      throw new Error(`Failed to list installations: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  invalidateTokenCache(): void {
    logger.info('Invalidating GitHub App installation token cache');
    this.installationTokenCache = null;
  }
}

let githubAppAuth: GitHubAppAuth | null = null;

export function getGitHubAppAuth(): GitHubAppAuth | null {
  if (!config.github.appId || !config.github.privateKey) {
    return null;
  }

  if (!githubAppAuth) {
    githubAppAuth = new GitHubAppAuth({
      appId: config.github.appId,
      privateKey: config.github.privateKey,
      installationId: config.github.installationId,
    });
  }

  return githubAppAuth;
}

export function isGitHubAppConfigured(): boolean {
  return !!(config.github.appId && config.github.privateKey);
}

export async function discoverInstallations(): Promise<void> {
  const githubAuth = getGitHubAppAuth();
  if (!githubAuth) {
    logger.error('GitHub App not configured. Please set GITHUB_APP_ID and GITHUB_PRIVATE_KEY environment variables.');
    return;
  }

  try {
    const installations = await githubAuth.listInstallations();
    
    if (installations.length === 0) {
      logger.info('No GitHub App installations found. Please install the app on at least one organization or repository.');
      return;
    }

    logger.info('GitHub App installations found:');
    installations.forEach((installation, index) => {
      logger.info(`  ${index + 1}. ${installation.account.login} (${installation.account.type}) - ID: ${installation.id}`);
    });

    if (!config.github.installationId) {
      logger.info('To use GitHub integration, set GITHUB_INSTALLATION_ID to one of the IDs above.');
    } else {
      const currentInstallation = installations.find(inst => inst.id.toString() === config.github.installationId);
      if (currentInstallation) {
        logger.info(`Currently configured for: ${currentInstallation.account.login} (${currentInstallation.account.type})`);
      } else {
        logger.warn(`Configured installation ID ${config.github.installationId} not found in available installations.`);
      }
    }
  } catch (error) {
    logger.error('Failed to discover GitHub App installations:', error);
  }
}

export async function getGitHubTokenForCLI(): Promise<string | null> {
  // First try to get the token from environment variable
  if (config.github.token) {
    logger.info('Using GITHUB_TOKEN from environment variables for Git CLI operations');
    return config.github.token;
  }

  // If no environment token, try to get one from GitHub App
  const githubAuth = getGitHubAppAuth();
  if (githubAuth) {
    try {
      logger.info('Obtaining GitHub App installation token for Git CLI operations');
      const token = await githubAuth.getInstallationToken();
      return token;
    } catch (error) {
      logger.error('Failed to obtain GitHub App installation token:', error);
      return null;
    }
  }

  logger.warn('No GitHub authentication configured. Set GITHUB_TOKEN or configure GitHub App (GITHUB_APP_ID, GITHUB_PRIVATE_KEY, GITHUB_INSTALLATION_ID)');
  return null;
}