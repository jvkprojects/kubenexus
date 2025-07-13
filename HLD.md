graph TB
    subgraph "Frontend (React + TypeScript)"
        FE[React Frontend<br/>Port 3000]
        LOGIN[Login Page]
        DASH[Dashboard]
        CLUSTERS[Clusters Page]
        USERS[Users Management]
        MONITORING[Monitoring]
        AUDIT[Audit Logs]
        PROFILE[Profile]
    end

    subgraph "API Gateway (Port 80)"
        GW[API Gateway<br/>FastAPI<br/>Port 80]
        AUTH_MW[Auth Middleware]
        RBAC_MW[RBAC Middleware]
        PROXY_MW[Proxy Middleware]
    end

    subgraph "Microservices Backend"
        AUTH[Auth Service<br/>Port 8000]
        CLUSTER[Cluster Manager<br/>Port 8001]
        SRE[SRE Agent<br/>Port 8002]
        AUDIT_SVC[Audit Service<br/>Port 8003]
        METRICS[Metrics Service<br/>Port 8004]
        TERMINAL[Terminal Service<br/>Port 8005]
    end

    subgraph "Data Layer"
        PG[(PostgreSQL<br/>Database)]
        REDIS[(Redis<br/>Cache/Sessions)]
    end

    subgraph "AI/ML Components"
        ANOMALY[Anomaly Detection<br/>Isolation Forest]
        PATTERN[Pattern Analysis<br/>DBSCAN Clustering]
        RECOMMENDATIONS[ML Recommendations]
    end

    subgraph "External Integrations"
        K8S_CLUSTERS[Kubernetes Clusters<br/>EKS, GKE, AKS, On-Premise]
        SSO[SSO/LDAP/AD<br/>Integration]
    end

    FE --> GW
    LOGIN --> AUTH
    GW --> AUTH_MW
    AUTH_MW --> RBAC_MW
    RBAC_MW --> PROXY_MW
    
    GW --> AUTH
    GW --> CLUSTER
    GW --> SRE
    GW --> AUDIT_SVC
    GW --> METRICS
    GW --> TERMINAL

    AUTH --> PG
    AUTH --> REDIS
    CLUSTER --> PG
    SRE --> PG
    SRE --> REDIS
    AUDIT_SVC --> PG
    METRICS --> PG
    METRICS --> REDIS
    
    SRE --> ANOMALY
    SRE --> PATTERN
    SRE --> RECOMMENDATIONS
    
    CLUSTER --> K8S_CLUSTERS
    TERMINAL --> K8S_CLUSTERS
    AUTH --> SSO

    style FE fill:#e1f5fe
    style GW fill:#f3e5f5
    style AUTH fill:#e8f5e8
    style SRE fill:#fff3e0
    style PG fill:#ffebee
    style REDIS fill:#fce4ec