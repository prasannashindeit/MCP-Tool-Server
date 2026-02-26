# MCP Kali Server

**MCP Kali Server** is a cybersecurity dashboard and API bridge that connects AI models to Kali Linux security tools via the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). It features a built-in **AI Chat** interface with real-time tool orchestration, multi-provider support, and dynamic tool discovery.

## 🚀 Features

- 🤖 **AI Chat Dashboard** — Chat with an AI agent that can orchestrate security tools in real-time directly from your browser
- 🔌 **MCP Protocol** — Standard MCP server for external clients (Claude Desktop, 5ire, Cursor, etc.)
- 🔍 **Dynamic Tool Discovery** — AI auto-discovers available tools from the MCP server; add a tool once, use it everywhere
- 📊 **Agent Activity Visibility** — See what the AI is doing: *Thinking → Orchestrating → Analyzing*
- 🧠 **Multi-Provider AI** — Supports Google Gemini, OpenAI, Anthropic, and Ollama (local)
- 🔐 **Client-Side Key Storage** — API keys stored in `localStorage`, never sent to the server
- ⚡ **Tool Caching** — Cached MCP tool definitions for fast response times

### Security Tools

| Tool | Capability |
|------|-----------|
| **Nmap** | Port scanning, service detection, OS fingerprinting |
| **Gobuster** | Directory/file brute-forcing, DNS subdomain enumeration |
| **Dirb** | Web content discovery |
| **Nikto** | Web server vulnerability scanning |
| **SQLMap** | SQL injection detection & exploitation |
| **Metasploit** | Exploit execution, payload delivery |
| **Hydra** | Online password brute-forcing |
| **John the Ripper** | Offline password hash cracking |
| **WPScan** | WordPress vulnerability scanning |
| **Enum4linux** | Windows/Samba/SMB enumeration |
| **Custom Commands** | Execute arbitrary shell commands |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  Web Dashboard                   │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ AI Chat  │  │  Tools   │  │ Health Check  │  │
│  └────┬─────┘  └──────────┘  └───────────────┘  │
│       │                                          │
│  ┌────▼─────────────────────────────────────┐    │
│  │         Flask API (kali_server.py)       │    │
│  │  ┌─────────────┐  ┌──────────────────┐   │    │
│  │  │ AI Providers │  │   MCP Client     │   │    │
│  │  │ (Gemini,GPT) │  │ (Tool Discovery) │   │    │
│  │  └─────────────┘  └───────┬──────────┘   │    │
│  └────────────────────────────┼──────────────┘    │
│                               │                   │
│  ┌────────────────────────────▼──────────────┐    │
│  │       MCP Server (mcp_server.py)          │    │
│  │  nmap │ sqlmap │ hydra │ nikto │ ...      │    │
│  └───────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**Two ways to use the tools:**
1. **Dashboard AI Chat** — The browser-based chat uses the MCP client internally for fast, cached tool orchestration
2. **External MCP Clients** — Claude Desktop, 5ire, Cursor, etc. connect directly to the MCP server

---

## 🛠️ Installation

### Quick Start

```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 kali_server.py
```

Open **http://127.0.0.1:5000** in your browser to access the dashboard.

### Command Line Options

```bash
python3 kali_server.py                              # localhost:5000 (default)
python3 kali_server.py --ip 0.0.0.0                 # all interfaces (⚠️ use caution)
python3 kali_server.py --ip 192.168.1.100 --port 8080  # specific IP + port
python3 kali_server.py --debug                      # verbose logging
```

### Kali Package (if available)

```bash
sudo apt install mcp-kali-server
kali-server
```

---

## 🤖 Using the AI Chat

1. Click **AI Chat** in the sidebar
2. Click the ⚙️ **Settings** button in the top bar
3. Select your **AI Provider** (Gemini, OpenAI, Anthropic, or Ollama)
4. Enter your **API Key** (stored locally, never sent to the server)
5. Choose a **Model** or type a custom model name
6. Start chatting! Try:
   - `"Scan 192.168.1.1 with nmap for open ports"`
   - `"Check example.com for SQL injection vulnerabilities"`
   - `"Run a directory brute force on http://target.com"`

### Discover Tools

Click **🔍 Discover Tools** in the chat header to see all available MCP tools in real-time.

---

## 🔌 External MCP Client Setup

### Local (same machine)

```bash
python3 mcp_server.py --server http://127.0.0.1:5000
```

### Remote (via SSH tunnel — recommended)

```bash
# Terminal 1 — SSH tunnel
ssh -L 5000:localhost:5000 user@KALI_IP

# Terminal 2 — MCP client
python3 mcp_server.py --server http://127.0.0.1:5000
```

### Claude Desktop Config

Edit your config file:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

See [mcp-kali-server.json](mcp-kali-server.json) for an example configuration.

### 5ire Desktop

Add an MCP with command: `python3 /path/to/mcp_server.py http://KALI_IP:5000`

---

## 📁 Project Structure

```
MCP-Kali-Server/
├── kali_server.py       # Flask API + MCP Client + Dashboard
├── mcp_server.py        # MCP Server (tool definitions)
├── ai_providers.py      # AI provider abstraction (Gemini, OpenAI, Anthropic, Ollama)
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Dashboard UI
├── static/
│   ├── css/style.css    # Dashboard styles
│   └── js/app.js        # Dashboard logic
└── mcp-kali-server.json # Claude Desktop config example
```

---

## 🔮 Other Possibilities

The AI agent can execute arbitrary commands, enabling tasks beyond the built-in tools:

- **Memory forensics** with Volatility — process enumeration, DLL injection checks
- **Disk forensics** with SleuthKit — timeline generation, file carving
- **Network analysis** with tcpdump/Wireshark — packet capture and analysis
- **CTF solving** — automated recon and exploitation in real-time

---

## Articles Using This Tool

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**How MCP is Revolutionizing Offensive Security**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## ⚠️ Disclaimer

This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.

The author assumes no responsibility for misuse.
