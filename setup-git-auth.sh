#!/bin/bash

# Function to generate GitHub App JWT token
generate_github_app_jwt() {
    local app_id="$1"
    local private_key="$2"
    
    # Generate JWT payload
    local now=$(date +%s)
    local iat=$((now - 60))
    local exp=$((now + 600))  # 10 minutes
    
    # Create JWT header (base64url encoded)
    local header='{"alg":"RS256","typ":"JWT"}'
    local header_b64=$(echo -n "$header" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
    
    # Create JWT payload (base64url encoded)
    local payload="{\"iat\":$iat,\"exp\":$exp,\"iss\":\"$app_id\"}"
    local payload_b64=$(echo -n "$payload" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
    
    # Create signature
    local signing_input="${header_b64}.${payload_b64}"
    
    # Write private key to temp file for openssl
    local temp_key=$(mktemp)
    echo "$private_key" > "$temp_key"
    
    # Generate signature using openssl
    local signature=$(echo -n "$signing_input" | openssl dgst -sha256 -sign "$temp_key" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n')
    
    # Clean up temp file
    rm "$temp_key"
    
    # Return JWT
    echo "${signing_input}.${signature}"
}

# Function to get GitHub App installation token
get_github_app_token() {
    local app_id="$1"
    local private_key="$2" 
    local installation_id="$3"
    
    echo "Generating GitHub App installation token..." >&2
    
    # Generate JWT
    local jwt=$(generate_github_app_jwt "$app_id" "$private_key")
    if [ $? -ne 0 ] || [ -z "$jwt" ]; then
        echo "Error: Failed to generate GitHub App JWT"
        return 1
    fi
    
    # Get installation token from GitHub API
    local response=$(curl -s -X POST \
        -H "Authorization: Bearer $jwt" \
        -H "Accept: application/vnd.github.v3+json" \
        -H "User-Agent: Claude-Code-Slack-Bot/1.0.0" \
        "https://api.github.com/app/installations/$installation_id/access_tokens")
    
    if [ $? -ne 0 ]; then
        echo "Error: Failed to call GitHub API"
        return 1
    fi
    
    # Extract token from JSON response
    local token=$(echo "$response" | grep -o '"token":"[^"]*' | cut -d'"' -f4)
    
    if [ -z "$token" ]; then
        echo "Error: Failed to extract token from GitHub API response"
        echo "API Response: $response"
        return 1
    fi
    
    echo "$token"
}

# Function to setup Git authentication with a token
setup_git_auth_with_token() {
    local token="$1"
    local source="$2"
    local is_github_app="$3"
    
    echo "Setting up Git authentication with $source..."
    
    # Clean the token by removing any newlines or whitespace
    local clean_token=$(echo "$token" | tr -d '\n\r' | xargs)
    
    # Export the token for use by child processes (like Claude's git commands)
    export GITHUB_TOKEN="$clean_token"
    
    # Use different authentication format based on token type
    if [ "$is_github_app" = "true" ]; then
        # GitHub App installation tokens use x-access-token format
        echo "https://x-access-token:${clean_token}@github.com" > ~/.git-credentials
        git config --global url."https://x-access-token:${clean_token}@github.com/".insteadOf "https://github.com/"
        echo "Using GitHub App installation token format (x-access-token)"
    else
        # Personal access tokens use the token directly or with x-oauth-basic
        echo "https://${clean_token}:x-oauth-basic@github.com" > ~/.git-credentials
        git config --global url."https://${clean_token}:x-oauth-basic@github.com/".insteadOf "https://github.com/"
        echo "Using personal access token format (x-oauth-basic)"
    fi
    
    # Configure Git credential helper specifically for GitHub
    git config --global credential.https://github.com.username "$clean_token"
    
    # Set Git user for commits (optional but recommended)
    BOT_NAME="${BOT_NAME:-claudebot}"
    git config --global user.name "$BOT_NAME"
    git config --global user.email "$BOT_NAME@anthropic.com"
    
    echo "Git authentication configured successfully with $source"
    echo "GITHUB_TOKEN exported for child processes"
}

# Main authentication logic
setup_git_authentication() {
    # First priority: Check if GITHUB_TOKEN is already set
    if [ -n "$GITHUB_TOKEN" ]; then
        setup_git_auth_with_token "$GITHUB_TOKEN" "GitHub token from environment" "false"
        return
    fi
    
    # Second priority: Try to get GitHub App installation token
    if [ -n "$GITHUB_APP_ID" ] && [ -n "$GITHUB_PRIVATE_KEY" ] && [ -n "$GITHUB_INSTALLATION_ID" ]; then
        echo "GitHub App credentials found, attempting to generate installation token..."
        
        local app_token
        app_token=$(get_github_app_token "$GITHUB_APP_ID" "$GITHUB_PRIVATE_KEY" "$GITHUB_INSTALLATION_ID")
        
        if [ $? -eq 0 ] && [ -n "$app_token" ]; then
            # Export the token as GITHUB_TOKEN for the Node.js application
            export GITHUB_TOKEN="$app_token"
            setup_git_auth_with_token "$app_token" "GitHub App installation token" "true"
            return
        else
            echo "Warning: Failed to generate GitHub App installation token, falling back to no authentication"
        fi
    fi
    
    # No authentication available
    echo "Warning: No GitHub authentication configured."
    echo "Set GITHUB_TOKEN or configure GitHub App (GITHUB_APP_ID, GITHUB_PRIVATE_KEY, GITHUB_INSTALLATION_ID)"
    echo "Git authentication for private repositories will not work."
}

# Run the authentication setup
setup_git_authentication