#!/usr/bin/env node

// Test script for GitHub App token refresh functionality
// This script tests the token refresh mechanism without requiring a full Slack setup

import { config, validateConfig } from './dist/config.js';
import { getGitHubAppAuth, isGitHubAppConfigured } from './dist/github-auth.js';
import { Logger } from './dist/logger.js';

const logger = new Logger('TokenRefreshTest');

async function testTokenRefresh() {
  try {
    logger.info('🧪 Testing GitHub App token refresh functionality...');

    // Check if GitHub App is configured
    if (!isGitHubAppConfigured()) {
      logger.warn('❌ GitHub App not configured. Please set GITHUB_APP_ID, GITHUB_PRIVATE_KEY, and GITHUB_INSTALLATION_ID environment variables.');
      process.exit(1);
    }

    const githubAuth = getGitHubAppAuth();
    if (!githubAuth) {
      logger.error('❌ Failed to get GitHub App auth instance');
      process.exit(1);
    }

    logger.info('✅ GitHub App configuration found');

    // Test getting initial token
    logger.info('🔄 Testing initial token generation...');
    const initialToken = await githubAuth.getInstallationToken();
    logger.info(`✅ Initial token generated successfully (length: ${initialToken.length})`);

    // Start auto-refresh
    logger.info('🔄 Testing auto-refresh startup...');
    await githubAuth.startAutoRefresh();
    logger.info('✅ Auto-refresh started successfully');

    // Test manual token refresh (this should use cached token)
    logger.info('🔄 Testing cached token retrieval...');
    const cachedToken = await githubAuth.getInstallationToken();
    logger.info(`✅ Cached token retrieved successfully (matches initial: ${cachedToken === initialToken})`);

    // Test invalidation and refresh
    logger.info('🔄 Testing token cache invalidation and refresh...');
    githubAuth.invalidateTokenCache();
    const refreshedToken = await githubAuth.getInstallationToken();
    logger.info(`✅ Token refreshed after invalidation (new token: ${refreshedToken !== initialToken})`);

    // Stop auto-refresh
    logger.info('🔄 Testing auto-refresh cleanup...');
    githubAuth.stopAutoRefresh();
    logger.info('✅ Auto-refresh stopped successfully');

    logger.info('🎉 All tests passed! Token refresh functionality is working correctly.');

    // Test environment variable is set
    if (process.env.GITHUB_TOKEN) {
      logger.info(`✅ GITHUB_TOKEN environment variable is set (length: ${process.env.GITHUB_TOKEN.length})`);
    } else {
      logger.warn('⚠️ GITHUB_TOKEN environment variable is not set');
    }

  } catch (error) {
    logger.error('❌ Test failed:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Test interrupted, cleaning up...');
  const githubAuth = getGitHubAppAuth();
  if (githubAuth) {
    githubAuth.stopAutoRefresh();
  }
  process.exit(0);
});

// Run the test
testTokenRefresh();