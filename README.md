# 🛡️ Sovereign AI Security

> *AI-driven security tooling built on NVIDIA Morpheus, Triton Inference Server, and custom Python pipelines for high-performance, local threat detection without cloud exposure.*

---

## 🎯 Overview

This repository implements an AI-augmented security layer for the sovereign lab. It leverages GPU-accelerated inference to perform:

- **Real-time secret scanning** — Detect exposed credentials, API keys, and PII in codebases and logs
- **Anomaly detection** — Identify suspicious patterns in network traffic and system behavior
- **Threat analysis** — Classify and prioritize security threats using BERT-backed inference
- **Local inference** — All processing stays on-premises, zero cloud exposure

**Status:** ✅ Active — Morpheus pipeline operational, Triton running, scanning enabled

---

## 🧰 Technology Stack

```text
🤖 AI Framework    ::  NVIDIA Morpheus (cybersecurity AI pipeline)
🖥️ Inference       ::  NVIDIA Triton Inference Server
🧠 Model           ::  BERT tokenizer (local, no cloud APIs)
🐍 Language        ::  Python 3.x
🎮 Acceleration    ::  CUDA / NVIDIA GPU
🐳 Deployment      ::  Docker containerized
📊 Integration     ::  Prometheus metrics, Grafana dashboards
```

---

## 🏗️ Architecture

```
[Security Data Input]
   ├── Log files
   ├── Configuration files
   ├── Source code
   └── Network packets
         ↓
[Morpheus Pipeline]
   ├── Data ingestion
   ├── Preprocessing
   └── Tokenization
         ↓
[Triton Inference Server]
   ├── BERT embeddings
   ├── Classification
   └── Threat scoring
         ↓
[Threat Detection]
   ├── Secret scanning
   ├── Anomaly detection
   └── Pattern matching
         ↓
[Alert & Report Output]
   ├── Prometheus metrics
   ├── Grafana dashboards
   ├── Log aggregation
   └── Incident response
```

---

## 🚀 Key Components

### 🔍 AI Secret Scanner (`scan_secrets_ia_pro.py`)

Professional-grade secret and PII detection using BERT tokenizer backed by NVIDIA Triton Inference Server.

**Capabilities:**
- Detects exposed credentials (API keys, passwords, tokens)
- Identifies personally identifiable information (PII)
- Scans codebases, configuration files, and logs
- Provides confidence scores for each finding

**Usage:**

```bash
python scan_secrets_ia_pro.py \
  --input /path/to/codebase \
  --output secrets-report.json \
  --triton-server localhost:8001 \
  --model-name bert-secret-detection
```

### ⚡ Lightweight Scanner (`scan_secrets_ia.py`)

Simplified bridge script for rapid scanning in resource-constrained environments.

**Advantages:**
- Minimal dependencies
- Same detection logic as pro version
- Faster startup time
- Suitable for edge deployments

**Usage:**

```bash
python scan_secrets_ia.py --path /target/directory
```

### 🔗 Morpheus Integration

Real-time security data processing pipeline:

```bash
# Start Morpheus pipeline
morpheus run pipeline-linear \
  --input-file security-logs.csv \
  --output-file detections.csv \
  --plugin-path ./morpheus_plugins/
```

---

## 📊 Detection Examples

### Secret Detection

```python
# Detects patterns like:
- AWS Access Keys: AKIA********************
- GitHub Tokens: ghp_****
- Database Passwords: password=***
- API Keys: sk_live_****
```

### PII Detection

```python
# Identifies:
- Email addresses
- Phone numbers
- Social security numbers
- Credit card numbers
- Home addresses
```

### Anomaly Scoring

```python
# Risk levels:
- LOW (0-30%): Potential non-secret matches
- MEDIUM (30-70%): Suspicious patterns
- HIGH (70-90%): Likely sensitive data
- CRITICAL (90%+): Confirmed secrets
```

---

## 🚀 Deployment

### Prerequisites

- NVIDIA GPU (24 GB+ VRAM recommended)
- NVIDIA Docker support
- Docker Compose
- Python 3.8+

### Quick Start

```bash
# Clone repository
git clone https://github.com/Dinaverse/sovereign-ai-security
cd sovereign-ai-security

# Start services
docker-compose up -d

# Verify Triton is running
curl localhost:8000/v2/health/ready

# Verify Morpheus connectivity
python -c "from morpheus.config import Config; print('Morpheus ready')"
```

### Docker Deployment

```bash
# Build custom image
docker build -t sovereign-ai-security .

# Run with GPU support
docker run --gpus all \
  -p 8000:8000 \
  -p 8001:8001 \
  -v /data:/data \
  sovereign-ai-security
```

---

## 🔌 Lab Integration

This security tooling operates within the broader sovereign lab:

| Component | Repository | Integration |
|-----------|-----------|-------------|
| **Security Automation** | [`cybersecurity-lab-automation`](https://github.com/Dinaverse/cybersecurity-lab-automation) | Feeds findings to agents |
| **LLM Inference** | [`local-ai-sovereign-stack`](https://github.com/Dinaverse/local-ai-sovereign-stack) | Uses Ollama for threat analysis |
| **Infrastructure** | [`sovereign-ai-infrastructure`](https://github.com/Dinaverse/sovereign-ai-infrastructure) | Deployed on Arch-GPU node |
| **Workflow Automation** | [`n8n-automation-hub`](https://github.com/Dinaverse/n8n-automation-hub) | Incident response triggers |
| **Monitoring** | `sovereign-ai-infrastructure/grafana/` | Dashboard visualization |

---

## 📁 Directory Structure

```
sovereign-ai-security/
├── README.md                          (this file)
├── docker-compose.yml                 Service orchestration
├── Dockerfile.morpheus                Morpheus image
├── Dockerfile.triton                  Triton image
├── src/
│   ├── scan_secrets_ia_pro.py        Professional secret scanner
│   ├── scan_secrets_ia.py             Lightweight scanner
│   ├── morpheus_pipeline.py           Pipeline orchestration
│   └── threat_classifier.py           AI threat classification
├── models/
│   ├── bert-secret-detection/         Secret detection model
│   └── anomaly-detector/              Anomaly detection model
├── morpheus_plugins/
│   ├── custom_stage.py                Custom pipeline stages
│   └── threat_scorer.py               Threat scoring logic
├── config/
│   ├── morpheus-config.yaml           Pipeline configuration
│   ├── triton-config.yaml             Triton settings
│   └── prometheus.yml                 Metrics config
└── docs/
    ├── MORPHEUS_SETUP.md              Morpheus installation
    ├── THREAT_ANALYSIS.md             Threat scoring details
    └── INTEGRATION_GUIDE.md           Lab integration steps
```

---

## 🔐 Security Features

### Local Processing
- All data processing happens on-premises
- No cloud APIs or external services
- Complete data ownership and control

### Confidence Scoring
- Each detection includes confidence level
- Helps reduce false positives
- Enable filtering by risk threshold

### Batch Processing
- Scan multiple files/directories
- Parallel processing on GPUs
- Generate comprehensive reports

### Integration Points
- **Prometheus** — Metrics export for monitoring
- **Grafana** — Dashboard visualization
- **n8n** — Workflow triggers for incident response
- **Syslog** — Log aggregation integration

---

## 📊 Monitoring & Metrics

### Prometheus Metrics

```bash
# Metrics exported:
morpheus_detections_total          # Total detections
morpheus_secrets_found             # Secrets discovered
morpheus_pii_detected              # PII instances
morpheus_threat_score_mean         # Average threat score
morpheus_processing_time_seconds   # Scan duration
triton_inference_latency           # Model inference time
```

### Grafana Dashboards

- **Security Overview** — Daily detection summary
- **Threat Timeline** — Historical threat patterns
- **Scanner Performance** — Processing efficiency metrics
- **False Positive Rate** — Detection accuracy tracking

---

## 🐛 Troubleshooting

### Triton Not Starting

```bash
# Check Triton logs
docker logs sovereign-ai-security-triton

# Verify model directory
ls -la /var/lib/triton/models/

# Test Triton connectivity
curl -v localhost:8000/v2/model_config/bert-secret-detection
```

### Morpheus Pipeline Errors

```bash
# Validate pipeline config
morpheus validate config.yaml

# Enable debug logging
export MORPHEUS_DEBUG=1
morpheus run pipeline-linear ...

# Check dependencies
python -m morpheus --version
```

### GPU Out of Memory

```bash
# Reduce batch size in config
batch_size: 32  # Lower from default 256

# Monitor GPU usage
nvidia-smi -l 1

# Or enable CPU fallback (slower)
USE_CPU=1 python scan_secrets_ia.py
```

---

## 🔗 Related Repositories

| Repository | Purpose |
|------------|---------|
| [`cybersecurity-lab-automation`](https://github.com/Dinaverse/cybersecurity-lab-automation) | Security agents & automation |
| [`local-ai-sovereign-stack`](https://github.com/Dinaverse/local-ai-sovereign-stack) | LLM inference backend |
| [`sovereign-ai-infrastructure`](https://github.com/Dinaverse/sovereign-ai-infrastructure) | Architecture & deployment |
| [`n8n-automation-hub`](https://github.com/Dinaverse/n8n-automation-hub) | Workflow orchestration |

---

## 📖 Documentation

- **[Morpheus Setup Guide](docs/MORPHEUS_SETUP.md)** — Installation & configuration
- **[Threat Analysis](docs/THREAT_ANALYSIS.md)** — Scoring and classification
- **[Integration Guide](docs/INTEGRATION_GUIDE.md)** — Lab integration steps
- **[API Reference](docs/API_REFERENCE.md)** — REST API documentation

---

## ✅ Operational Status

| Component | Status | Last Verified |
|-----------|--------|---|
| Morpheus Pipeline | ✅ Active | 2026-07-05 |
| Triton Inference Server | ✅ Running | 2026-07-05 |
| BERT Models | ✅ Loaded | 2026-07-05 |
| Secret Scanner | ✅ Operational | 2026-07-05 |
| Prometheus Metrics | ✅ Exporting | 2026-07-05 |
| Grafana Dashboards | ✅ Updated | 2026-07-05 |

---

*Local threat detection. No cloud. No telemetry. Full control.*
