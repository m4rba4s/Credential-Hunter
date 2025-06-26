/*
 * Cloud Credentials Detection Rules
 * 
 * YARA rules for detecting cloud service credentials across multiple providers.
 * Designed for high accuracy with minimal false positives.
 */

rule aws_access_keys {
    meta:
        author = "ECH Security Team"
        description = "AWS Access Keys and Secret Keys"
        version = "1.2"
        date = "2024-01-15"
        category = "credentials"
        severity = "critical"
        reference = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
        
    strings:
        $aws_access_key_id = /AKIA[0-9A-Z]{16}/ nocase
        $aws_secret_access_key = /[A-Za-z0-9\/\+]{40}/ 
        $aws_session_token = /[A-Za-z0-9\/\+]{16,}==?/
        $aws_temp_creds = /ASIA[0-9A-Z]{16}/ nocase
        
        // Context strings to increase confidence
        $aws_context1 = "aws_access_key_id" nocase
        $aws_context2 = "aws_secret_access_key" nocase
        $aws_context3 = "AWS_ACCESS_KEY_ID" nocase
        $aws_context4 = "AWS_SECRET_ACCESS_KEY" nocase
        
    condition:
        ($aws_access_key_id or $aws_temp_creds) and
        (any of ($aws_context*) or $aws_secret_access_key)
}

rule azure_credentials {
    meta:
        author = "ECH Security Team"
        description = "Microsoft Azure Service Principal and Storage Account Credentials"
        version = "1.1" 
        date = "2024-01-15"
        category = "credentials"
        severity = "critical"
        
    strings:
        // Azure Service Principal
        $azure_client_id = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ nocase
        $azure_client_secret = /[A-Za-z0-9._~-]{34,}/
        $azure_tenant_id = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ nocase
        
        // Azure Storage Account Keys
        $azure_storage_key = /[A-Za-z0-9+/]{88}==/ 
        $azure_storage_sas = /\?sv=20[0-9]{2}-[0-9]{2}-[0-9]{2}&ss=[bfqt]+&srt=[sco]+&sp=[rwdlacup]+&se=20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}%3A[0-9]{2}%3A[0-9]{2}Z&st=20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}%3A[0-9]{2}%3A[0-9]{2}Z&spr=https&sig=[A-Za-z0-9%+/=]+/
        
        // Context strings
        $azure_context1 = "AZURE_CLIENT_ID" nocase
        $azure_context2 = "AZURE_CLIENT_SECRET" nocase
        $azure_context3 = "AZURE_TENANT_ID" nocase
        $azure_context4 = "DefaultEndpointsProtocol=https;AccountName=" nocase
        
    condition:
        (($azure_client_id and $azure_client_secret) or 
         $azure_storage_key or 
         $azure_storage_sas) and
        any of ($azure_context*)
}

rule gcp_credentials {
    meta:
        author = "ECH Security Team"
        description = "Google Cloud Platform Service Account Keys and API Keys"
        version = "1.0"
        date = "2024-01-15"
        category = "credentials"
        severity = "critical"
        
    strings:
        // GCP Service Account Key (JSON format indicators)
        $gcp_type = "\"type\": \"service_account\"" nocase
        $gcp_project_id = "\"project_id\":" nocase
        $gcp_private_key_id = "\"private_key_id\":" nocase
        $gcp_private_key = "\"private_key\": \"-----BEGIN PRIVATE KEY-----" nocase
        $gcp_client_email = "\"client_email\":" nocase
        $gcp_client_id = "\"client_id\":" nocase
        $gcp_auth_uri = "\"auth_uri\": \"https://accounts.google.com/o/oauth2/auth\"" nocase
        $gcp_token_uri = "\"token_uri\": \"https://oauth2.googleapis.com/token\"" nocase
        
        // GCP API Keys
        $gcp_api_key = /AIza[0-9A-Za-z\-_]{35}/
        
        // Context
        $gcp_context1 = "GOOGLE_APPLICATION_CREDENTIALS" nocase
        $gcp_context2 = "GOOGLE_API_KEY" nocase
        
    condition:
        (3 of ($gcp_type, $gcp_project_id, $gcp_private_key_id, $gcp_private_key, $gcp_client_email) or
         $gcp_api_key) and
        (any of ($gcp_context*) or 3 of ($gcp_*))
}

rule digital_ocean_tokens {
    meta:
        author = "ECH Security Team"
        description = "DigitalOcean API Tokens and Spaces Access Keys"
        version = "1.0"
        date = "2024-01-15"
        category = "credentials"
        severity = "high"
        
    strings:
        $do_token = /dop_v1_[a-f0-9]{64}/
        $do_spaces_key = /[A-Z0-9]{20}/
        $do_spaces_secret = /[A-Za-z0-9+/]{40}/
        
        // Context
        $do_context1 = "DIGITALOCEAN_TOKEN" nocase
        $do_context2 = "DO_PAT" nocase
        $do_context3 = "SPACES_ACCESS_KEY_ID" nocase
        $do_context4 = "SPACES_SECRET_ACCESS_KEY" nocase
        
    condition:
        ($do_token or ($do_spaces_key and $do_spaces_secret)) and
        any of ($do_context*)
}

rule heroku_api_keys {
    meta:
        author = "ECH Security Team"
        description = "Heroku API Keys and OAuth Tokens"
        version = "1.0"
        date = "2024-01-15"
        category = "credentials"
        severity = "medium"
        
    strings:
        $heroku_api_key = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/
        $heroku_oauth = /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/
        
        // Context
        $heroku_context1 = "HEROKU_API_KEY" nocase
        $heroku_context2 = "heroku_api_key" nocase
        
    condition:
        ($heroku_api_key or $heroku_oauth) and
        any of ($heroku_context*)
}