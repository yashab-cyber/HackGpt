<div align="center">
  <img src="public/hackgpt-logo.png" alt="HackGPT Enterprise Logo" width="400" height="auto">
  
  <h1>🚀 HackGPT Enterprise</h1>
  <h3>AI-Powered Penetration Testing Platform</h3>
  
  <p>
    <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
    <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-orange.svg" alt="Multi-Platform">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
    <img src="https://img.shields.io/badge/AI-Multi--Provider%20(7%20Providers%20%7C%2026%2B%20Models)-purple.svg" alt="AI Multi-Provider">
  </p>
  <p>
    <img src="https://img.shields.io/badge/Architecture-Microservices-red.svg" alt="Microservices">
    <img src="https://img.shields.io/badge/Cloud-Docker%20%7C%20Kubernetes-lightblue.svg" alt="Cloud Native">
    <img src="https://img.shields.io/badge/Version-2026.07.beta.4-success.svg" alt="Version 2026.07.beta.4">
    <img src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg" alt="Production Ready">
  </p>
</div>

**HackGPT Enterprise** is a production-ready, cloud-native AI-powered penetration testing platform designed for enterprise security teams. It combines advanced AI, machine learning, microservices architecture, and comprehensive security frameworks to deliver professional-grade cybersecurity assessments.

**Created by [Yashab Alam](https://github.com/yashab-cyber)**

> 💰 **Support the Project**: [Donate to HackGPT Development](DONATE.md) | Help us build the future of AI-powered penetration testing!

## 🏢 Enterprise Features

### 🤖 Advanced AI Engine — Multi-Provider Support
- **7 AI Providers**: OpenAI, Anthropic (Claude), Google (Gemini), DeepSeek, GLM (Zhipu), Local LLMs (Ollama), OpenRouter
- **26+ AI Models**: GPT-5, GPT-5.6, o3, o4-mini, Claude Sonnet 5, Opus 4.8, Gemini 3.5 Flash, 3.1 Pro, DeepSeek R1, and more
- **Runtime Model Switching**: Change AI models on-the-fly with automatic provider fallback
- **Machine Learning**: Pattern recognition, anomaly detection, behavioral analysis
- **Zero-Day Detection**: ML-powered vulnerability discovery and correlation
- **Risk Intelligence**: CVSS scoring, impact assessment, exploit prioritization
- **Automated Reporting**: Executive summaries, technical details, compliance mapping

### 🛡️ Enterprise Security & Compliance
- **Authentication**: RBAC + LDAP/Active Directory integration
- **Authorization**: Role-based permissions (Admin, Lead, Senior, Pentester, Analyst)
- **Compliance**: OWASP, NIST, ISO27001, SOC2, PCI-DSS frameworks
- **Audit Logging**: Comprehensive activity tracking and forensics
- **Data Protection**: AES-256-GCM encryption, JWT tokens, secure sessions

### 🏗️ Cloud-Native Architecture
- **Microservices**: Docker containers with Kubernetes orchestration
- **Service Discovery**: Consul-based service registry
- **Load Balancing**: Nginx reverse proxy with auto-scaling
- **Multi-Cloud**: AWS, Azure, GCP deployment support
- **High Availability**: Circuit breakers, health checks, failover

### ⚡ Performance & Scalability
- **Parallel Processing**: Celery-based distributed task execution
- **Multi-Layer Caching**: Redis + memory caching with TTL management
- **Database**: PostgreSQL with connection pooling and replication
- **Real-Time**: WebSocket dashboards with live updates
- **Auto-Scaling**: Worker pools adapt to workload demands

### 📊 Enterprise Reporting & Analytics
- **Dynamic Reports**: HTML, PDF, JSON, XML, CSV export formats
- **Real-Time Dashboards**: Prometheus + Grafana monitoring stack
- **Log Analytics**: ELK stack (Elasticsearch + Kibana) integration
- **Executive Summaries**: AI-generated business impact assessments
- **Compliance Reports**: Framework-specific compliance documentation

## 🚀 Quick Start

### Prerequisites
- **Operating System**: Linux (Ubuntu/Debian/RHEL/CentOS), macOS, or Windows WSL2
- **Python**: 3.8+ with pip and virtual environment support
- **Docker**: For containerized deployment (recommended)
- **Resources**: Minimum 4GB RAM, 20GB disk space

### Enterprise Installation

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/HackGPT.git
cd HackGPT

# Run enterprise installer (sets up all services)
chmod +x install.sh
./install.sh

# Configure environment
cp .env.example .env
# Edit .env with your API keys and settings
nano .env

# Verify installation
python3 test_installation.py
```

### Deployment Options

#### 1. Standalone Enterprise Mode
```bash
# Activate virtual environment
source venv/bin/activate

# Run enterprise application
python3 advance_hackgpt.py
```

#### 2. API Server Mode
```bash
# Start REST API server
python3 advance_hackgpt.py --api

# API available at: http://localhost:8000
# Health check: http://localhost:8000/api/health
```

#### 3. Web Dashboard Mode
```bash
# Start web dashboard
python3 advance_hackgpt.py --web

# Dashboard available at: http://localhost:8080
```

#### 4. Full Enterprise Stack (Recommended)
```bash
# Deploy complete microservices stack
docker-compose up -d

# Services:
# - API Server: http://localhost:8000
# - Web Dashboard: http://localhost:8080  
# - Monitoring: http://localhost:9090 (Prometheus)
# - Analytics: http://localhost:3000 (Grafana)
# - Logs: http://localhost:5601 (Kibana)
```

#### 5. Direct Assessment Mode
```bash
# Run immediate assessment
python3 advance_hackgpt.py \
  --target example.com \
  --scope "Web application and API" \
  --auth-key "ENTERPRISE-2025-AUTH" \
  --assessment-type black-box \
  --compliance OWASP
```

## 🏗️ Enterprise Architecture

### Core Components

```mermaid
graph TD
    A[Load Balancer/Nginx] --> B[HackGPT API Gateway]
    B --> C[Authentication Service]
    B --> D[AI Engine Service] 
    B --> E[Exploitation Service]
    B --> F[Reporting Service]
    
    C --> G[LDAP/AD]
    D --> H[OpenAI API]
    D --> H2[Anthropic API]
    D --> H3[Google Gemini API]
    D --> H4[DeepSeek API]
    D --> H5[GLM / Zhipu API]
    D --> H6[OpenRouter API]
    D --> I[Local LLM / Ollama]
    D --> J[ML Models]
    
    E --> K[Parallel Processor]
    F --> L[Report Generator]
    
    K --> M[Celery Workers]
    M --> N[Redis Queue]
    
    B --> O[PostgreSQL]
    B --> P[Redis Cache]
    
    Q[Prometheus] --> R[Grafana]
    S[Elasticsearch] --> T[Kibana]
```

### Service Stack

| Service | Purpose | Port | Technology |
|---------|---------|------|------------|
| **hackgpt-app** | Main application | 8000, 8080 | Python/Flask |
| **hackgpt-worker** | Background tasks | - | Celery |
| **hackgpt-database** | Data persistence | 5432 | PostgreSQL 15 |
| **hackgpt-redis** | Cache & queues | 6379 | Redis 7 |
| **prometheus** | Metrics collection | 9090 | Prometheus |
| **grafana** | Monitoring dashboard | 3000 | Grafana |
| **elasticsearch** | Log aggregation | 9200 | Elasticsearch |
| **kibana** | Log visualization | 5601 | Kibana |
| **consul** | Service discovery | 8500 | Consul |
| **nginx** | Load balancer | 80, 443 | Nginx |

## 🔧 Configuration

### Enterprise Configuration (`config.ini`)

The configuration file supports 200+ options across multiple categories:

```ini
[app]
debug = false
environment = production
max_sessions = 100

[database]
url = postgresql://hackgpt:hackgpt123@localhost:5432/hackgpt
pool_size = 20
backup_enabled = true

[ai]
default_model = gpt-5
default_provider = 
openai_api_key = your_key_here
anthropic_api_key = your_key_here
google_api_key = your_key_here
enable_local_fallback = true
confidence_threshold = 0.8

[security]
secret_key = your_secret_here
jwt_algorithm = HS256
rate_limit_enabled = true

[ldap]
server = ldaps://your-ldap-server.com:636
bind_dn = cn=admin,dc=example,dc=com

[compliance]
frameworks = OWASP,NIST,ISO27001,SOC2,PCI-DSS
auto_compliance_check = true

[cloud]
docker_host = unix:///var/run/docker.sock
service_registry_backend = consul
```

### Environment Variables (`.env`)

Over 100 environment variables for enterprise deployment:

```bash
# Core Services
DATABASE_URL=postgresql://hackgpt:hackgpt123@localhost:5432/hackgpt
REDIS_URL=redis://localhost:6379/0

# AI Configuration — Multi-Provider
HACKGPT_MODEL=gpt-5               # Any model from ai_engine/model_registry.py
OPENAI_API_KEY=your_openai_api_key
ANTHROPIC_API_KEY=your_anthropic_api_key
GOOGLE_API_KEY=your_google_api_key
DEEPSEEK_API_KEY=your_deepseek_api_key
GLM_API_KEY=your_glm_api_key
OPENROUTER_API_KEY=your_openrouter_api_key
LOCAL_LLM_ENDPOINT=http://localhost:11434

# Security
SECRET_KEY=your_secret_key
JWT_SECRET_KEY=your_jwt_secret
LDAP_SERVER=ldaps://your-ldap.com:636

# Cloud Providers
AWS_ACCESS_KEY_ID=your_aws_key
AZURE_SUBSCRIPTION_ID=your_azure_id
GCP_PROJECT_ID=your_gcp_project

# Monitoring
PROMETHEUS_ENDPOINT=http://localhost:9090
GRAFANA_API_KEY=your_grafana_key
ELASTICSEARCH_ENDPOINT=http://localhost:9200
```

## 🎯 Enterprise Penetration Testing

### Enhanced 6-Phase Methodology

#### Phase 1: Intelligence Gathering & Reconnaissance
**Enterprise Features**:
- AI-powered OSINT automation
- Multi-source data aggregation
- Threat intelligence correlation
- Cloud asset discovery (AWS, Azure, GCP)
- **Tools**: theHarvester, Amass, Subfinder, Shodan API

#### Phase 2: Advanced Scanning & Enumeration  
**Enterprise Features**:
- Parallel distributed scanning
- Service fingerprinting with ML classification
- Vulnerability correlation across assets
- Zero-day pattern detection
- **Tools**: Nmap, Masscan, Nuclei, HTTPx, Naabu

#### Phase 3: Vulnerability Assessment
**Enterprise Features**:
- CVSS v3.1 automated scoring
- Business impact analysis
- Exploit availability assessment  
- Compliance framework mapping
- **Tools**: OpenVAS, Nexpose integration, custom scanners

#### Phase 4: Exploitation & Post-Exploitation
**Enterprise Features**:
- Safe-mode exploitation with approval workflows
- Privilege escalation enumeration
- Lateral movement mapping
- Data exfiltration simulation
- **Tools**: Metasploit, CrackMapExec, BloodHound, custom exploits

#### Phase 5: Enterprise Reporting & Analytics
**Enterprise Features**:
- Executive dashboard with KPIs
- Technical vulnerability details
- Compliance gap analysis
- Risk prioritization matrix
- **Outputs**: HTML, PDF, JSON, XML, compliance reports

#### Phase 6: Verification & Retesting
**Enterprise Features**:
- Automated remediation verification
- Regression testing for fixes
- Continuous security monitoring
- Trend analysis and metrics
- **Features**: Scheduled retests, delta reporting

## 📊 Enterprise Interfaces

### 1. Command Line Interface (CLI)
```bash
# Interactive enterprise mode
python3 advance_hackgpt.py

# Available options:
# 1. Full Enterprise Pentest (All 6 Phases)
# 2. Run Specific Phase
# 3. Custom Assessment Workflow
# 4. View Reports & Analytics
# 5. Real-time Dashboard
# 6. User & Permission Management
# 7. System Configuration
# 8. Compliance Management
# 9. Cloud & Container Management
# 10. AI Engine Configuration
```

### 2. REST API Server
```bash
# Start API server
python3 advance_hackgpt.py --api

# Available endpoints:
# GET  /api/health - Health check
# POST /api/pentest/start - Start assessment
# GET  /api/sessions - List sessions
# GET  /api/reports/{id} - Get report
# POST /api/users - User management
# GET  /api/compliance - Compliance status
```

### 3. Web Dashboard
```bash
# Start web dashboard
python3 advance_hackgpt.py --web

# Features:
# - Real-time assessment monitoring
# - Interactive vulnerability management
# - Executive summary dashboard
# - User and role management
# - System configuration
# - Compliance reporting
```

### 4. Voice Commands (Enterprise)
```bash
# Voice command mode
python3 advance_hackgpt.py --voice

# Supported commands:
# "Start enterprise assessment of example.com"
# "Show compliance dashboard"
# "Generate executive report"
# "Scale worker pool to 10"
```

## 🔐 Enterprise Security

### Authentication & Authorization
- **Multi-Factor Authentication**: LDAP/AD + JWT tokens
- **Role-Based Access Control**: Granular permissions matrix
- **Session Management**: Secure session handling with timeout
- **API Security**: Rate limiting, CORS, input validation

### Data Protection
- **Encryption**: AES-256-GCM for data at rest
- **Transport Security**: TLS 1.3 for data in transit  
- **Key Management**: Automated key rotation
- **Audit Logging**: Comprehensive activity tracking

### Compliance Frameworks
| Framework | Coverage | Reports | Automation |
|-----------|----------|---------|------------|
| **OWASP Top 10** | ✅ Full | ✅ Yes | ✅ Automated |
| **NIST Cybersecurity Framework** | ✅ Full | ✅ Yes | ✅ Automated |
| **ISO 27001** | ✅ Partial | ✅ Yes | ✅ Semi-automated |
| **SOC 2** | ✅ Partial | ✅ Yes | ✅ Semi-automated |
| **PCI DSS** | ✅ Partial | ✅ Yes | ✅ Manual |

## 📈 Monitoring & Analytics

### Real-Time Monitoring
- **System Metrics**: CPU, memory, disk, network utilization
- **Application Metrics**: Request rates, response times, error rates
- **Security Metrics**: Vulnerability counts, risk scores, remediation rates
- **Business Metrics**: Assessment coverage, compliance scores

### Alerting
- **Email Alerts**: Critical vulnerabilities, system issues
- **Slack Integration**: Real-time notifications to security teams
- **Webhook Support**: Custom integrations with SIEM systems
- **Dashboard Alerts**: Visual indicators and notifications

### Analytics Dashboard
```bash
# Access Grafana dashboard
http://localhost:3000
# Login: admin / hackgpt123

# Pre-configured dashboards:
# - HackGPT System Overview
# - Assessment Performance Metrics  
# - Vulnerability Trend Analysis
# - User Activity Dashboard
# - Compliance Status Overview
```

## 🛠️ Advanced Usage

### Multi-Provider AI Models
```python
from ai_engine import get_advanced_ai_engine, list_all_models, get_available_providers

# Initialize with a specific model
engine = get_advanced_ai_engine(model_id='claude-sonnet-5')

# Switch models at runtime
engine.set_model('gemini-3.5-flash')

# List all 26+ available models
for model in engine.list_available_models():
    status = "✅" if model['available'] else "❌"
    print(f"{status} {model['display_name']} ({model['provider']})")

# Check available providers
for provider in get_available_providers():
    print(f"{provider['name']}: {provider['model_count']} models")
```

### Custom Compliance Frameworks
```python
# Add custom compliance framework
from security.compliance import ComplianceFrameworkMapper

mapper = ComplianceFrameworkMapper()
mapper.add_framework('CUSTOM', {
    'sql_injection': 'SEC-01',
    'xss': 'SEC-02',
    # ... custom mappings
})
```

### Kubernetes Deployment
```yaml
# Deploy to Kubernetes cluster
kubectl apply -f k8s/
```

### Multi-Cloud Deployment
```bash
# Deploy to AWS
python3 advance_hackgpt.py --deploy aws

# Deploy to Azure  
python3 advance_hackgpt.py --deploy azure

# Deploy to GCP
python3 advance_hackgpt.py --deploy gcp
```

## 🧪 Testing & Development

### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests  
pytest tests/integration/

# End-to-end tests
pytest tests/e2e/

# Security tests
bandit -r .
safety check
```

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Pre-commit hooks
pre-commit install

# Code formatting
black .
flake8 .
mypy .
```

## 📦 Enterprise Deployment

### Docker Swarm
```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.yml hackgpt
```

### Kubernetes
```bash
# Create namespace
kubectl create namespace hackgpt

# Deploy applications
kubectl apply -f k8s/

# Scale workers
kubectl scale deployment hackgpt-worker --replicas=10
```

### Cloud Platforms

#### AWS Deployment
```bash
# ECS deployment
aws ecs create-cluster --cluster-name hackgpt
aws ecs create-service --service-name hackgpt-api
```

#### Azure Deployment  
```bash
# ACI deployment
az container create --resource-group hackgpt --name hackgpt-api
```

#### GCP Deployment
```bash
# GKE deployment
gcloud container clusters create hackgpt-cluster
kubectl apply -f k8s/
```

## 🔧 Troubleshooting

### Common Enterprise Issues

#### Database Connection Issues
```bash
# Check PostgreSQL status
systemctl status postgresql
docker logs hackgpt-database

# Test connection
python3 -c "from database import get_db_manager; print(get_db_manager().test_connection())"
```

#### Redis Cache Issues
```bash
# Check Redis status
redis-cli ping
docker logs hackgpt-redis

# Clear cache
redis-cli FLUSHALL
```

#### AI Engine Issues
```bash
# List available AI models and providers
python3 -c "from ai_engine import list_all_models; [print(m.display_name, m.provider.value) for m in list_all_models()]"

# Test provider connectivity
python3 -c "from ai_engine.providers import ProviderFactory; print(ProviderFactory.get_available_providers())"

# Check local LLM (Ollama)
ollama list
ollama run llama3.3:70b
```

#### Worker Pool Issues
```bash
# Check Celery workers
celery -A performance.parallel_processor inspect active

# Restart workers
docker-compose restart hackgpt-worker
```

### Performance Optimization
```bash
# Database optimization
python3 -c "from database import optimize_database; optimize_database()"

# Cache warming
python3 -c "from performance.cache_manager import warm_cache; warm_cache()"

# Worker scaling
docker-compose up --scale hackgpt-worker=10
```

## 📄 Enterprise License

This project is licensed under the MIT License with additional enterprise terms:

- **Commercial Use**: Permitted with attribution
- **Enterprise Support**: Available through support channels
- **Compliance**: Tool usage must comply with applicable laws
- **Liability**: Limited liability for enterprise deployments

## 🆘 Enterprise Support

### Support Channels
- **Enterprise Support**: yashabalam707@gmail.com
- **Technical Issues**: https://github.com/yashab-cyber/HackGPT/issues
- **Feature Requests**: https://github.com/yashab-cyber/HackGPT/discussions
- **Security Issues**: yashabalam707@gmail.com
- **WhatsApp Business**: [Join Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

### Professional Services
- **Implementation**: Custom deployment and configuration
- **Training**: Security team training and certification  
- **Custom Development**: Feature development and integration
- **24/7 Support**: Enterprise support packages available

### Connect with the Team
- **Yashab Alam**: [GitHub](https://github.com/yashab-cyber) | [Instagram](https://www.instagram.com/yashab.alam) | [LinkedIn](https://www.linkedin.com/in/yashab-alam)

## 📊 Project Statistics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | 15,000+ |
| **Enterprise Dependencies** | 90+ |
| **Configuration Options** | 200+ |
| **Environment Variables** | 100+ |
| **Docker Services** | 12 |
| **Supported Compliance Frameworks** | 5 |
| **Penetration Testing Tools** | 50+ |
| **API Endpoints** | 25+ |
| **Deployment Platforms** | 6+ |

## 🗺️ Roadmap

### Version 2.1 (Q3 2025)
- [x] Multi-provider AI support (OpenAI, Anthropic, Google, DeepSeek, GLM, Local, OpenRouter)
- [x] 26+ model catalog with runtime switching
- [x] Provider fallback chain and automatic detection
- [ ] ML-based false positive reduction
- [ ] Integration with popular SIEM systems

### Version 2.2 (Q4 2025)
- [ ] Streaming responses from all providers
- [ ] Automated penetration testing workflows
- [ ] Advanced cloud security assessments
- [ ] Integration with CI/CD pipelines

### Version 3.0 (Q1 2026)
- [ ] Fully autonomous security assessments
- [ ] Advanced AI attack simulation
- [ ] Quantum-safe cryptography
- [ ] Next-generation threat detection

## 🙏 Contributors

### Core Development Team
- **Lead Developer & Founder**: [Yashab Alam](https://github.com/yashab-cyber) - [@yashab.alam](https://www.instagram.com/yashab.alam) | [LinkedIn](https://www.linkedin.com/in/yashab-alam)
- **AI/ML Engineer**: Enterprise AI Team
- **Security Engineer**: Enterprise Security Team
- **DevOps Engineer**: Enterprise Infrastructure Team


- 💬 **WhatsApp**: [Business Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

### Acknowledgments
- OpenAI for GPT-5 and o-series API access
- Anthropic for the Claude model family
- Google DeepMind for Gemini models
- DeepSeek, Zhipu AI (GLM), and OpenRouter
- Ollama team for local LLM support
- Docker & Kubernetes communities
- Security research community
- Open source tool developers

### 💰 Support HackGPT Development
Your donations help accelerate development and support the growing cybersecurity community:

**Cryptocurrency Donations (Recommended):**
- **Solana (SOL)**: `5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT`
- **Bitcoin (BTC)**: `bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c`

**Traditional Payment:**
- **PayPal**: [yashabalam707@gmail.com](https://paypal.me/yashab07)
- **Email**: yashabalam707@gmail.com

**📄 Full Donation Information**: [DONATE.md](DONATE.md) - Support tiers, funding goals, and recognition programs

## ⚖️ Legal & Compliance

**⚠️ IMPORTANT LEGAL NOTICE**

HackGPT Enterprise is designed for authorized security testing only:

- ✅ **Authorized Use**: Only use against systems you own or have explicit written permission
- ✅ **Compliance**: Follow all applicable laws, regulations, and industry standards
- ✅ **Responsible Disclosure**: Report vulnerabilities through proper channels
- ✅ **Documentation**: Maintain audit trails and documentation
- ❌ **Unauthorized Use**: Never use against systems without permission
- ❌ **Malicious Activity**: Not for criminal or malicious purposes

**The developers and contributors are not liable for misuse of this platform.**

---

---

<div align="center">
  <img src="public/hackgpt-logo.png" alt="HackGPT Enterprise" width="150" height="auto">
  
  <h3>🚀 HackGPT Enterprise - Transforming Cybersecurity Through AI 🚀</h3>
  <p><em>Made with ❤️ by Yashab Alam for enterprise security teams worldwide</em></p>
  
  <p>
    <a href="https://github.com/yashab-cyber/HackGPT">⭐ Star us on GitHub</a> |
    <a href="DONATE.md">💰 Support Development</a> |
    <a href="#-enterprise-support">📞 Get Support</a> |
    <a href="#-contributors">🤝 Contribute</a> |
    <a href="LICENSE">📄 License</a>
  </p>
</div>

### 🔗 Connect with Yashab Alam

<div align="center">
  <p>
    <a href="https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q">💬 WhatsApp Business</a> |
    <a href="https://discord.gg/eXPjM3Hxwb">👾 Discord Channel</a>
  </p>
  
  <p>
    <strong>Founder & Lead Developer:</strong> Yashab Alam<br>
    <a href="https://github.com/yashab-cyber">🔧 GitHub</a> |
    <a href="https://www.instagram.com/yashabcyber">📸 Instagram</a> |
    <a href="https://x.com/Yashab_cyber">🐦 X (Twitter)</a> |
    <a href="https://www.linkedin.com/in/yashab-alam">💼 LinkedIn</a> |
    <a href="https://www.threads.com/@yashabcyber">🧵 Threads</a>
  </p>
  
  <p>
    <strong>Email Contacts:</strong><br>
    📧 <a href="mailto:yashabalam9@gmail.com">yashabalam9@gmail.com</a> | 📧 <a href="mailto:yashabalam707@gmail.com">yashabalam707@gmail.com</a>
  </p>
</div>