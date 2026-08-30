"""S-13b 演示①：LangChain 经 MCP 接入 Meridian DSA（闭环：authorize→revocation_witness→pay→balance→verify_receipt→vendor）。

用法（在仓库根）：
    cargo build -p meridian-mcp --release
    demos/.venv/Scripts/python.exe demos/langchain_demo.py

`MultiServerMCPClient` 以 stdio 拉起 `target/release/meridian-mcp`（内嵌真实聚合器 +
WAL），把 6 个工具暴露给 LangChain。本脚本用 LangChain 的 `get_tools()` 拿工具、
`ainvoke` 依次调用，闭环序列与 common 里完全一致（含逐字节自检）。
"""

import asyncio
import json
from pathlib import Path

from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_mcp_adapters.tools import load_mcp_tools

from meridian_demo_common import run_closed_loop

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "release" / "meridian-mcp.exe"
WAL_DIR = str(Path(__file__).resolve().parent / ".wal")


async def main() -> None:
    config = {
        "meridian": {
            "command": str(BIN),
            "args": [],
            "env": {"MERIDIAN_WAL_DIR": WAL_DIR},
            "transport": "stdio",
        }
    }
    # 0.1.0 关键坑：`get_tools()` 的工具**每次调用都新建一个 MCP 会话**（→ 新子进程 →
    # 新聚合器，authorize 与 pay 就落到不同内核了）。必须用 `session()` 绑定**单一**会话，
    # 工具共享同一 server 进程，DSA 委托状态才连续。
    client = MultiServerMCPClient(config)
    async with client.session("meridian") as session:
        tools = {t.name: t for t in await load_mcp_tools(session)}
        expected = {
            "authorize",
            "pay",
            "balance",
            "attest",
            "verify_receipt",
            "revocation_witness",
        }
        assert expected <= set(tools), f"MCP 工具不全: {sorted(set(tools) - expected)} 缺?"

        async def call_tool(name: str, args: dict) -> tuple[bool, dict]:
            msg = await tools[name].ainvoke(args)
            # 0.1.0 的 ainvoke 直接返回内容块 list（[{"type":"text","text":...}]）。
            if isinstance(msg, list):
                content = msg
            else:
                content = getattr(msg, "content", msg)
            if isinstance(content, list):
                text = "".join(
                    b.get("text", "") if isinstance(b, dict) else str(b)
                    for b in content
                )
            else:
                text = str(content)
            body = json.loads(text)
            return not body.get("error"), body

        await run_closed_loop(call_tool, log=lambda s: print(f"  [langchain] {s}"))


if __name__ == "__main__":
    asyncio.run(main())
