import { getGitHubTokenForCLI } from './github-auth.js';
import { Logger } from './logger.js';

const logger = new Logger('GitCLIAuth');

export interface GitEnvironmentVariables {
  GITHUB_TOKEN?: string;
  [key: string]: string | undefined;
}

export async function getGitEnvironmentVariables(): Promise<GitEnvironmentVariables> {
  const env: GitEnvironmentVariables = {};
  
  try {
    const githubToken = await getGitHubTokenForCLI();
    if (githubToken) {
      env.GITHUB_TOKEN = githubToken;
      logger.info('GitHub token configured for Git CLI operations');
    } else {
      logger.warn('No GitHub token available for Git CLI operations');
    }
  } catch (error) {
    logger.error('Failed to obtain GitHub token for Git CLI:', error);
  }

  return env;
}

export async function getGitCommands(): Promise<{
  gitPush: string;
  gitPull: string;
  gitClone: (repoUrl: string, directory?: string) => string;
  gitRemoteSetUrl: (remoteName: string, url: string) => string;
}> {
  const env = await getGitEnvironmentVariables();
  const tokenPrefix = env.GITHUB_TOKEN ? `GITHUB_TOKEN=${env.GITHUB_TOKEN} ` : '';

  return {
    gitPush: `${tokenPrefix}git push`,
    gitPull: `${tokenPrefix}git pull`,
    gitClone: (repoUrl: string, directory?: string) => 
      `${tokenPrefix}git clone ${repoUrl}${directory ? ` ${directory}` : ''}`,
    gitRemoteSetUrl: (remoteName: string, url: string) => 
      `${tokenPrefix}git remote set-url ${remoteName} ${url}`,
  };
}

export async function createGitCommand(command: string, useAuth: boolean = true): Promise<string> {
  if (!useAuth) {
    return command;
  }

  try {
    const token = await getGitHubTokenForCLI();
    if (token) {
      return `GITHUB_TOKEN=${token} ${command}`;
    }
    return command;
  } catch (error) {
    logger.error('Failed to get GitHub token for Git command:', error);
    return command;
  }
}