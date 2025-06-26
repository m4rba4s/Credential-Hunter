/*
 * Database Credentials Detection Rules
 * 
 * YARA rules for detecting database connection strings, credentials,
 * and related authentication information across various database systems.
 */

rule mysql_credentials {
    meta:
        author = "ECH Security Team"
        description = "MySQL Database Connection Strings and Credentials"
        version = "1.1"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "high"
        
    strings:
        // Connection string patterns
        $mysql_conn1 = /mysql:\/\/[^:]+:[^@]+@[^\/]+\/[^\s;'"]+/ nocase
        $mysql_conn2 = /Server=[^;]+;Database=[^;]+;Uid=[^;]+;Pwd=[^;]+/ nocase
        $mysql_conn3 = /host=[^;]+.*user=[^;]+.*password=[^;]+.*database=[^;]+/ nocase
        
        // JDBC URLs
        $mysql_jdbc = /jdbc:mysql:\/\/[^:]+:[0-9]+\/[^\s;?'"]+\?.*user=[^&]+.*password=[^&]+/ nocase
        
        // Configuration format
        $mysql_config1 = /(mysql_username|mysql_password|mysql_host|mysql_database)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $mysql_config2 = /(MYSQL_USER|MYSQL_PASSWORD|MYSQL_HOST|MYSQL_DATABASE)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $mysql_context1 = "mysql" nocase
        $mysql_context2 = "mariadb" nocase
        $mysql_context3 = "DATABASE_URL" nocase
        
    condition:
        (any of ($mysql_conn*) or any of ($mysql_jdbc*) or 2 of ($mysql_config*)) and
        any of ($mysql_context*)
}

rule postgresql_credentials {
    meta:
        author = "ECH Security Team"
        description = "PostgreSQL Database Connection Strings and Credentials"
        version = "1.1"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "high"
        
    strings:
        // Connection string patterns
        $postgres_conn1 = /postgres:\/\/[^:]+:[^@]+@[^\/]+\/[^\s;'"]+/ nocase
        $postgres_conn2 = /postgresql:\/\/[^:]+:[^@]+@[^\/]+\/[^\s;'"]+/ nocase
        $postgres_libpq = /host=[^\\s]+.*user=[^\\s]+.*password=[^\\s]+.*dbname=[^\\s]+/ nocase
        
        // JDBC URLs
        $postgres_jdbc = /jdbc:postgresql:\/\/[^:]+:[0-9]+\/[^\s;?'"]+.*user=[^&]+.*password=[^&]+/ nocase
        
        // Configuration format
        $postgres_config1 = /(pg_username|pg_password|pg_host|pg_database)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $postgres_config2 = /(POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_HOST|POSTGRES_DB)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $postgres_config3 = /(DATABASE_USERNAME|DATABASE_PASSWORD|DATABASE_HOST)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $postgres_context1 = "postgres" nocase
        $postgres_context2 = "postgresql" nocase
        $postgres_context3 = "psql" nocase
        
    condition:
        (any of ($postgres_conn*) or $postgres_libpq or $postgres_jdbc or 2 of ($postgres_config*)) and
        any of ($postgres_context*)
}

rule mongodb_credentials {
    meta:
        author = "ECH Security Team"
        description = "MongoDB Connection Strings and Credentials"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "high"
        
    strings:
        // Connection string patterns
        $mongo_conn1 = /mongodb:\/\/[^:]+:[^@]+@[^\/]+\/[^\s;'"]*/ nocase
        $mongo_conn2 = /mongodb\+srv:\/\/[^:]+:[^@]+@[^\/]+\/[^\s;'"]*/ nocase
        
        // Configuration format
        $mongo_config1 = /(mongo_username|mongo_password|mongo_host|mongo_database)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $mongo_config2 = /(MONGO_USER|MONGO_PASSWORD|MONGO_HOST|MONGO_DB)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $mongo_config3 = /(MONGODB_URI|MONGODB_URL)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $mongo_context1 = "mongodb" nocase
        $mongo_context2 = "mongo" nocase
        $mongo_context3 = "atlas" nocase
        
    condition:
        (any of ($mongo_conn*) or any of ($mongo_config*)) and
        any of ($mongo_context*)
}

rule redis_credentials {
    meta:
        author = "ECH Security Team"
        description = "Redis Connection Strings and Auth Passwords"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "medium"
        
    strings:
        // Connection string patterns
        $redis_conn1 = /redis:\/\/[^:]*:[^@]+@[^\/]+/ nocase
        $redis_conn2 = /rediss:\/\/[^:]*:[^@]+@[^\/]+/ nocase
        
        // Configuration format
        $redis_config1 = /(redis_password|redis_auth|redis_host)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $redis_config2 = /(REDIS_PASSWORD|REDIS_AUTH|REDIS_HOST|REDIS_URL)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // AUTH command
        $redis_auth = /AUTH\s+['"][^'"]+['"]/ nocase
        
        // Context indicators
        $redis_context1 = "redis" nocase
        $redis_context2 = "REDIS_URL" nocase
        
    condition:
        (any of ($redis_conn*) or any of ($redis_config*) or $redis_auth) and
        any of ($redis_context*)
}

rule mssql_credentials {
    meta:
        author = "ECH Security Team"
        description = "Microsoft SQL Server Connection Strings"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "high"
        
    strings:
        // Connection string patterns
        $mssql_conn1 = /Server=[^;]+;Database=[^;]+;User Id=[^;]+;Password=[^;]+/ nocase
        $mssql_conn2 = /Data Source=[^;]+;Initial Catalog=[^;]+;User ID=[^;]+;Password=[^;]+/ nocase
        $mssql_conn3 = /server=[^;]+;database=[^;]+;uid=[^;]+;pwd=[^;]+/ nocase
        
        // JDBC URLs
        $mssql_jdbc = /jdbc:sqlserver:\/\/[^:]+:[0-9]+;databaseName=[^;]+;user=[^;]+;password=[^;]+/ nocase
        
        // Configuration format
        $mssql_config1 = /(mssql_username|mssql_password|mssql_server)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $mssql_config2 = /(MSSQL_USER|MSSQL_PASSWORD|MSSQL_SERVER)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $mssql_context1 = "sqlserver" nocase
        $mssql_context2 = "mssql" nocase
        $mssql_context3 = "sql server" nocase
        
    condition:
        (any of ($mssql_conn*) or $mssql_jdbc or any of ($mssql_config*)) and
        any of ($mssql_context*)
}

rule oracle_credentials {
    meta:
        author = "ECH Security Team"
        description = "Oracle Database Connection Strings"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "high"
        
    strings:
        // Connection string patterns
        $oracle_tns = /\(DESCRIPTION\s*=\s*\(ADDRESS\s*=\s*\(PROTOCOL\s*=\s*TCP\)\s*\(HOST\s*=[^)]+\)\s*\(PORT\s*=[^)]+\)\)\s*\(CONNECT_DATA\s*=\s*\(SERVICE_NAME\s*=[^)]+\)\)\)/ nocase
        
        // JDBC URLs
        $oracle_jdbc = /jdbc:oracle:thin:@[^:]+:[0-9]+:[^\s;'"]+/ nocase
        $oracle_jdbc_sid = /jdbc:oracle:thin:[^\/]+\/[^@]+@[^:]+:[0-9]+:[^\s;'"]+/ nocase
        
        // Configuration format
        $oracle_config1 = /(oracle_username|oracle_password|oracle_host|oracle_sid)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $oracle_config2 = /(ORACLE_USER|ORACLE_PASSWORD|ORACLE_HOST|ORACLE_SID)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $oracle_context1 = "oracle" nocase
        $oracle_context2 = "TNS_ADMIN" nocase
        $oracle_context3 = "ORACLE_HOME" nocase
        
    condition:
        (any of ($oracle_*) or any of ($oracle_config*)) and
        any of ($oracle_context*)
}

rule elasticsearch_credentials {
    meta:
        author = "ECH Security Team"
        description = "Elasticsearch Connection Credentials"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "medium"
        
    strings:
        // Connection string patterns
        $elastic_conn1 = /https?:\/\/[^:]+:[^@]+@[^\/]+:9200/ nocase
        $elastic_conn2 = /elasticsearch:\/\/[^:]+:[^@]+@[^\/]+/ nocase
        
        // Configuration format
        $elastic_config1 = /(elastic_username|elastic_password|elasticsearch_url)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $elastic_config2 = /(ELASTIC_USER|ELASTIC_PASSWORD|ELASTICSEARCH_URL)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Context indicators
        $elastic_context1 = "elasticsearch" nocase
        $elastic_context2 = "elastic" nocase
        $elastic_context3 = ":9200" nocase
        
    condition:
        (any of ($elastic_conn*) or any of ($elastic_config*)) and
        any of ($elastic_context*)
}

rule cassandra_credentials {
    meta:
        author = "ECH Security Team"
        description = "Apache Cassandra Database Credentials"
        version = "1.0"
        date = "2024-01-15"
        category = "database_credentials"
        severity = "medium"
        
    strings:
        // Configuration format
        $cassandra_config1 = /(cassandra_username|cassandra_password|cassandra_host)\s*[:=]\s*['"][^'"]+['"]/ nocase
        $cassandra_config2 = /(CASSANDRA_USER|CASSANDRA_PASSWORD|CASSANDRA_HOST)\s*[:=]\s*['"][^'"]+['"]/ nocase
        
        // Connection details
        $cassandra_contact_points = /contact_points\s*[:=]\s*\[.*\]/ nocase
        $cassandra_auth = /auth_provider\s*[:=].*PlainTextAuthProvider/ nocase
        
        // Context indicators
        $cassandra_context1 = "cassandra" nocase
        $cassandra_context2 = "datastax" nocase
        $cassandra_context3 = ":9042" nocase
        
    condition:
        (any of ($cassandra_config*) or $cassandra_contact_points or $cassandra_auth) and
        any of ($cassandra_context*)
}