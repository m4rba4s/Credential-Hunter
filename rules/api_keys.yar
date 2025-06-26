/*
 * API Keys and Service Tokens Detection Rules
 * 
 * YARA rules for detecting various API keys, service tokens, and authentication credentials
 * from popular services and platforms.
 */

rule stripe_api_keys {
    meta:
        author = "ECH Security Team"
        description = "Stripe API Keys (Live and Test)"
        version = "1.1"
        date = "2024-01-15"
        category = "api_keys"
        severity = "critical"
        reference = "https://stripe.com/docs/keys"
        
    strings:
        // Live keys (critical)
        $stripe_live_secret = /sk_live_[a-zA-Z0-9]{24}/
        $stripe_live_publishable = /pk_live_[a-zA-Z0-9]{24}/
        $stripe_live_restricted = /rk_live_[a-zA-Z0-9]{24}/
        
        // Test keys (medium risk)
        $stripe_test_secret = /sk_test_[a-zA-Z0-9]{24}/
        $stripe_test_publishable = /pk_test_[a-zA-Z0-9]{24}/
        $stripe_test_restricted = /rk_test_[a-zA-Z0-9]{24}/
        
        // Webhook endpoints
        $stripe_webhook_secret = /whsec_[a-zA-Z0-9]{32}/
        
        // Context
        $stripe_context1 = "STRIPE_SECRET_KEY" nocase
        $stripe_context2 = "STRIPE_PUBLISHABLE_KEY" nocase
        $stripe_context3 = "stripe_api_key" nocase
        
    condition:
        any of ($stripe_*) and
        (any of ($stripe_context*) or any of ($stripe_*))
}

rule github_tokens {
    meta:
        author = "ECH Security Team"
        description = "GitHub Personal Access Tokens and App Tokens"
        version = "1.2"
        date = "2024-01-15"
        category = "tokens"
        severity = "high"
        reference = "https://docs.github.com/en/authentication"
        
    strings:
        // Personal Access Tokens
        $github_pat = /ghp_[a-zA-Z0-9]{36}/
        $github_pat_old = /[a-f0-9]{40}/
        
        // OAuth Tokens
        $github_oauth = /gho_[a-zA-Z0-9]{36}/
        
        // GitHub App tokens
        $github_app_token = /ghs_[a-zA-Z0-9]{36}/
        
        // Installation tokens
        $github_installation = /ghu_[a-zA-Z0-9]{36}/
        
        // Refresh tokens
        $github_refresh = /ghr_[a-zA-Z0-9]{36}/
        
        // Context
        $github_context1 = "GITHUB_TOKEN" nocase
        $github_context2 = "GH_TOKEN" nocase
        $github_context3 = "github_api_token" nocase
        $github_context4 = "Authorization: token" nocase
        
    condition:
        any of ($github_*) and
        (any of ($github_context*) or any of ($github_*))
}

rule slack_tokens {
    meta:
        author = "ECH Security Team"
        description = "Slack API Tokens and Webhook URLs"
        version = "1.0"
        date = "2024-01-15"
        category = "tokens"
        severity = "medium"
        
    strings:
        // Bot tokens
        $slack_bot_token = /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/
        
        // User tokens
        $slack_user_token = /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/
        
        // Webhook URLs
        $slack_webhook = /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9]{8,}\/B[a-zA-Z0-9]{8,}\/[a-zA-Z0-9]{24}/
        
        // Legacy tokens
        $slack_legacy = /xoxo-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}/
        
        // Context
        $slack_context1 = "SLACK_TOKEN" nocase
        $slack_context2 = "SLACK_BOT_TOKEN" nocase
        $slack_context3 = "SLACK_WEBHOOK" nocase
        
    condition:
        any of ($slack_*) and
        (any of ($slack_context*) or any of ($slack_*))
}

rule discord_tokens {
    meta:
        author = "ECH Security Team"
        description = "Discord Bot Tokens and Webhook URLs"
        version = "1.0"
        date = "2024-01-15"
        category = "tokens"
        severity = "medium"
        
    strings:
        // Bot tokens
        $discord_bot_token = /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/
        $discord_bot_token_alt = /[A-Za-z\d]{24}\.[\w-]{6}\.[\w-]{27}/
        
        // Webhook URLs
        $discord_webhook = /https:\/\/discord\.com\/api\/webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_-]{68}/
        $discord_webhook_alt = /https:\/\/discordapp\.com\/api\/webhooks\/[0-9]{17,19}\/[a-zA-Z0-9_-]{68}/
        
        // Context
        $discord_context1 = "DISCORD_TOKEN" nocase
        $discord_context2 = "DISCORD_BOT_TOKEN" nocase
        $discord_context3 = "DISCORD_WEBHOOK" nocase
        
    condition:
        any of ($discord_*) and
        (any of ($discord_context*) or any of ($discord_*))
}

rule sendgrid_api_keys {
    meta:
        author = "ECH Security Team"
        description = "SendGrid API Keys"
        version = "1.0"
        date = "2024-01-15"
        category = "api_keys"
        severity = "medium"
        
    strings:
        $sendgrid_api_key = /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/
        
        // Context
        $sendgrid_context1 = "SENDGRID_API_KEY" nocase
        $sendgrid_context2 = "sendgrid_api_key" nocase
        
    condition:
        $sendgrid_api_key and
        any of ($sendgrid_context*)
}

rule mailgun_api_keys {
    meta:
        author = "ECH Security Team"
        description = "Mailgun API Keys"
        version = "1.0"
        date = "2024-01-15"
        category = "api_keys"
        severity = "medium"
        
    strings:
        $mailgun_api_key = /key-[a-f0-9]{32}/
        $mailgun_signing_key = /[a-f0-9]{32}-[a-f0-9]{8}-[a-f0-9]{8}/
        
        // Context
        $mailgun_context1 = "MAILGUN_API_KEY" nocase
        $mailgun_context2 = "mailgun_api_key" nocase
        
    condition:
        ($mailgun_api_key or $mailgun_signing_key) and
        any of ($mailgun_context*)
}

rule twilio_credentials {
    meta:
        author = "ECH Security Team"
        description = "Twilio Account SID and Auth Token"
        version = "1.0"
        date = "2024-01-15"
        category = "credentials"
        severity = "medium"
        
    strings:
        $twilio_account_sid = /AC[a-f0-9]{32}/
        $twilio_auth_token = /[a-f0-9]{32}/
        $twilio_api_key = /SK[a-f0-9]{32}/
        
        // Context
        $twilio_context1 = "TWILIO_ACCOUNT_SID" nocase
        $twilio_context2 = "TWILIO_AUTH_TOKEN" nocase
        $twilio_context3 = "TWILIO_API_KEY" nocase
        
    condition:
        ($twilio_account_sid or $twilio_api_key) and
        any of ($twilio_context*)
}

rule square_tokens {
    meta:
        author = "ECH Security Team"
        description = "Square API Tokens and Application IDs"
        version = "1.0"
        date = "2024-01-15"
        category = "tokens"
        severity = "high"
        
    strings:
        // Production tokens
        $square_prod_token = /sq0atp-[a-zA-Z0-9_-]{22}/
        $square_prod_app_id = /sq0idp-[a-zA-Z0-9_-]{43}/
        
        // Sandbox tokens
        $square_sandbox_token = /sq0atb-[a-zA-Z0-9_-]{22}/
        $square_sandbox_app_id = /sq0idb-[a-zA-Z0-9_-]{43}/
        
        // Context
        $square_context1 = "SQUARE_ACCESS_TOKEN" nocase
        $square_context2 = "SQUARE_APPLICATION_ID" nocase
        
    condition:
        (any of ($square_prod_*) or any of ($square_sandbox_*)) and
        any of ($square_context*)
}

rule paypal_credentials {
    meta:
        author = "ECH Security Team"
        description = "PayPal API Credentials and Client IDs"
        version = "1.0"
        date = "2024-01-15"
        category = "credentials"
        severity = "high"
        
    strings:
        $paypal_client_id = /A[a-zA-Z0-9_-]{10,}\.A[a-zA-Z0-9_-]{10,}/
        $paypal_client_secret = /E[a-zA-Z0-9_-]{10,}/
        
        // Context
        $paypal_context1 = "PAYPAL_CLIENT_ID" nocase
        $paypal_context2 = "PAYPAL_CLIENT_SECRET" nocase
        $paypal_context3 = "paypal_api_username" nocase
        
    condition:
        ($paypal_client_id or $paypal_client_secret) and
        any of ($paypal_context*)
}