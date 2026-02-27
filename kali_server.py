#!/usr/bin/env python3

# This script connects the MCP AI agent to the PenForge API Server.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import asyncio
import time
from typing import Dict, Any, List, Optional
from flask import Flask, request, jsonify, render_template, Response
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from ai_providers import (
    get_provider, get_tools_for_provider, get_tool_endpoint,
    PROVIDER_INFO, SECURITY_TOOLS_SCHEMA
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ── Persistent background event loop ──────────────────────────────────────
# A single asyncio loop that lives for the lifetime of the process.
# All async MCP work is submitted here, avoiding the overhead of
# `asyncio.run()` (which creates + tears down a loop each time).
_bg_loop = asyncio.new_event_loop()

def _start_bg_loop(loop: asyncio.AbstractEventLoop):
    asyncio.set_event_loop(loop)
    loop.run_forever()

_bg_thread = threading.Thread(target=_start_bg_loop, args=(_bg_loop,), daemon=True)
_bg_thread.start()

def run_async(coro, timeout=300):
    """Run an async coroutine on the persistent background loop (thread-safe)."""
    future = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
    return future.result(timeout=timeout)


class MCPClient:
    """Helper class to manage MCP server connection and tool execution."""

    def __init__(self, server_script="mcp_server.py"):
        self.server_script = server_script
        self.params = StdioServerParameters(
            command=sys.executable,
            args=[os.path.join(os.path.dirname(__file__), server_script)],
            env=os.environ.copy()
        )
        # Cache: avoid spawning a subprocess on every single chat message
        self._tools_cache = None
        self._tools_cache_time = 0
        self._cache_ttl = 300  # 5 minutes

    async def get_tools(self, force_refresh=False):
        """Fetch available tools from the MCP server (cached)."""
        now = time.time()
        if not force_refresh and self._tools_cache and (now - self._tools_cache_time) < self._cache_ttl:
            logger.info("Using cached MCP tools list")
            return self._tools_cache

        try:
            async with stdio_client(self.params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    self._tools_cache = tools
                    self._tools_cache_time = now
                    logger.info(f"Fetched {len(tools.tools) if tools else 0} tools from MCP (fresh)")
                    return tools
        except Exception as e:
            logger.error(f"Failed to fetch tools from MCP: {str(e)}")
            return self._tools_cache  # Return stale cache if available

    async def call_tool(self, name, arguments):
        """Execute a tool via the MCP server."""
        try:
            async with stdio_client(self.params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool(name, arguments)
                    return result
        except Exception as e:
            logger.error(f"Failed to call MCP tool {name}: {str(e)}")
            return {"error": str(e), "success": False}

mcp_client = MCPClient()

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)


@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    return response


@app.route("/")
def dashboard():
    """Serve the web dashboard UI."""
    return render_template("index.html")


class CommandExecutor:
    """Class to handle command execution with better timeout management"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread function to continuously read stdout"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """Thread function to continuously read stderr"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """Execute the command and handle timeout gracefully"""
        logger.info(f"Executing command: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"Command timed out after {self.timeout} seconds. Terminating process.")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        timing = params.get("timing", "-T4")
        scripts = params.get("scripts", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nmap {scan_type}"

        if timing:
            command += f" {timing}"
        
        if ports:
            command += f" -p {ports}"

        if scripts:
            command += f" --script={scripts}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        command += f" {target} {service}"

        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


# Health check — cached to avoid spawning 10 subprocesses every poll
_health_cache = {"data": None, "time": 0}
_HEALTH_CACHE_TTL = 120  # seconds

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint (cached)."""
    now = time.time()
    if _health_cache["data"] and (now - _health_cache["time"]) < _HEALTH_CACHE_TTL:
        return jsonify(_health_cache["data"])

    essential_tools = ["nmap", "gobuster", "dirb", "nikto", "wpscan", "enum4linux", "sqlmap", "msfconsole", "hydra", "john"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False

    all_essential_tools_available = all(tools_status.values())

    payload = {
        "status": "healthy",
        "message": "PenForge Security API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    }
    _health_cache["data"] = payload
    _health_cache["time"] = now
    return jsonify(payload)

@app.route("/api/providers", methods=["GET"])
def list_providers():
    """Return available AI providers and their models."""
    return jsonify(PROVIDER_INFO)


@app.route("/api/mcp/tools", methods=["GET"])
def list_mcp_tools():
    """Fetch live tools list from MCP server (force-refreshes cache)."""
    tools_resp = run_async(mcp_client.get_tools(force_refresh=True))
    if not tools_resp or not hasattr(tools_resp, 'tools'):
        return jsonify({"tools": []})

    tools = []
    for t in tools_resp.tools:
        tools.append({
            "name": t.name,
            "description": t.description,
            "inputSchema": t.inputSchema
        })
    return jsonify({"tools": tools})


def _sse(event: str, data) -> str:
    """Format a single SSE frame."""
    payload = json.dumps(data) if not isinstance(data, str) else data
    return f"event: {event}\ndata: {payload}\n\n"


@app.route("/api/chat", methods=["POST"])
def ai_chat():
    """Chat with an AI model that can orchestrate security tools (SSE stream)."""
    params = request.json
    provider_name = params.get("provider", "")
    api_key = params.get("api_key", "")
    model = params.get("model", "")
    messages = params.get("messages", [])

    # ── Validate early (non-streaming errors) ──
    if not provider_name or not model:
        return jsonify({"error": "Provider and model are required"}), 400

    info = PROVIDER_INFO.get(provider_name, {})
    if info.get("needs_key") and not api_key:
        return jsonify({"error": "API key is required for " + provider_name}), 400

    def generate():
        try:
            # Step 1 — status: thinking
            yield _sse("status", {"message": "AI is thinking…"})

            provider = get_provider(provider_name, api_key=api_key, model=model)

            # Fetch MCP tools (uses persistent loop — fast when cached)
            mcp_tools_resp = run_async(mcp_client.get_tools())
            tools = []
            if mcp_tools_resp and hasattr(mcp_tools_resp, 'tools'):
                for t in mcp_tools_resp.tools:
                    tools.append({
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.inputSchema
                    })
            else:
                logger.warning("MCP tools not available, falling back to static schema")
                tools = get_tools_for_provider()

            # First AI call
            result = provider.chat(messages, tools=tools)

            if result.get("type") == "error":
                yield _sse("reply", {"reply": result["content"], "tool_used": None, "tool_result": None})
                yield _sse("done", {})
                return

            # ── Tool-call path ──
            if result.get("type") == "tool_call":
                tool_name = result["tool_name"]
                tool_args = result.get("tool_args", {})

                # Step 2 — status: calling tool
                yield _sse("status", {"message": f"Calling tool: {tool_name}"})

                logger.info(f"AI calling MCP tool: {tool_name} with args: {tool_args}")
                mcp_result = run_async(mcp_client.call_tool(tool_name, tool_args))

                tool_output = None
                if mcp_result and hasattr(mcp_result, 'content'):
                    content_text = ""
                    for content in mcp_result.content:
                        if hasattr(content, 'text'):
                            content_text += content.text
                    try:
                        tool_output = json.loads(content_text)
                    except Exception:
                        tool_output = {"stdout": content_text}
                else:
                    tool_output = {"error": "Failed to get response from MCP tool"}

                # Step 3 — stream tool result to frontend immediately
                yield _sse("tool_result", {
                    "tool_used": tool_name,
                    "tool_args": tool_args,
                    "tool_result": tool_output
                })

                # Build summary for analysis
                tool_summary = ""
                if tool_output:
                    if tool_output.get("stdout"):
                        tool_summary = tool_output["stdout"][:3000]
                    elif tool_output.get("error"):
                        tool_summary = f"Error: {tool_output['error']}"
                    elif tool_output.get("stderr"):
                        tool_summary = tool_output["stderr"][:2000]

                # Step 4 — status: analyzing
                yield _sse("status", {"message": "AI is analyzing results…"})

                analysis_messages = messages + [
                    {"role": "assistant", "content": f"I ran {tool_name} and here are the results:"},
                    {"role": "user", "content": f"Tool output:\n```\n{tool_summary}\n```\nPlease analyze these results and provide insights."}
                ]

                analysis = provider.chat(analysis_messages)
                analysis_text = analysis.get("content", "Tool executed successfully.")

                yield _sse("reply", {
                    "reply": analysis_text,
                    "tool_used": tool_name,
                    "tool_args": tool_args,
                    "tool_result": tool_output
                })
                yield _sse("done", {})
                return

            # ── Normal text response (no tool call) ──
            yield _sse("reply", {"reply": result.get("content", ""), "tool_used": None, "tool_result": None})
            yield _sse("done", {})

        except ValueError as e:
            yield _sse("error", {"error": str(e)})
        except Exception as e:
            logger.error(f"Error in chat endpoint: {str(e)}")
            logger.error(traceback.format_exc())
            yield _sse("error", {"error": f"Server error: {str(e)}"})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the PenForge API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    parser.add_argument("--ip", type=str, default="127.0.0.1", help="IP address to bind the server to (default: 127.0.0.1 for localhost only)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting PenForge API Server on {args.ip}:{API_PORT}")
    app.run(host=args.ip, port=API_PORT, debug=DEBUG_MODE)
