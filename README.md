## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/your-username/your-repo.git
cd your-repo
```

## Install the package:

```bash
pip install -e .
```

## Install with development dependencies:

```bash
pip install -e ".[dev]"
```

#Running Tests
This project uses pytest.

Run the test suite:

```bash
pytest tests/ -v
```

## The theory — what SYN scan actually does at the packet level

```bash
You                         Target
 |                             |
 |──── IP/TCP [SYN] ─────────>|   Raw packet, no OS involvement
 |                             |
 |<─── IP/TCP [SYN+ACK] ──────|   Port is OPEN
 |──── IP/TCP [RST] ─────────>|   You reset - never complete handshake
 |                             |
 ── OR ──
 |                             |
 |<─── IP/TCP [RST+ACK] ──────|   Port is CLOSED
 |                             |
 ── OR ──
 |                             |
 |       (no response)         |   Port is FILTERED
```
