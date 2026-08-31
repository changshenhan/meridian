"""S-13b 演示②：AutoGen 经 MCP 接入 Mist DSA（闭环：authorize→revocation_witness→pay→balance→verify_receipt→vendor）。

用法（在仓库根）：
    cargo build -p mist-mcp --release
    demos/.venv/Scripts/python.exe demos/autogen_demo.py

`autogen_ext.tools.mcp.mcp_server_tools` 把 MCP 工具注册为 AutoGen `Tool`（run_json 驱动，
0.7.x 接口）。**关键坑**：不显式传 `session` 时，每个 tool 每次调用都新建一个 MCP 会话
（→ 新子进程 → 新聚合器），authorize 与 pay 会落到不同内核。必须用 `mcp` 的 `stdio_client`
+ `ClientSession` 建一个共享会话传给 factory，6 个工具才同进程。
"""

import asyncio
import json
from pathlib import Path

from autogen_core import CancellationToken
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mist_demo_common import run_closed_loop

# autogen 的 schema→pydantic 转换只认它自己的 FORMAT_MAPPING；rmcp/schemars 对
# u64/u32/u8 字段标 `format: "uint64"` 等，autogen 不认识就抛
# FormatNotSupportedError。演示兼容层：把整数 format 映射到 int（值语义不变）。
# 这是 autogen 侧适配，不动服务器 schema。
import autogen_core.utils._json_to_pydantic as _json_to_pydantic

for _f in ("uint8", "uint16", "uint32", "uint64"):
    _json_to_pydantic.FORMAT_MAPPING[_f] = int

# rmcp 对 `Option<String>` 生成 JSON Schema 联合 `"type": ["string", "null"]`；autogen 的
# `_extract_field_type` 用 `json_type in TYPE_MAPPING` 查表，list 不可哈希 → TypeError。
# 演示兼容层：折叠 `[X, "null"]` 联合 → `X`（非 required 字段 autogen 会自动包 Optional，
# 值语义不变）。只动演示侧，服务器 schema 原样。
_orig_extract_field_type = _json_to_pydantic._JSONSchemaToPydantic._extract_field_type


def _fold_null_union(self, key, value, model_name, root_schema):
    t = value.get("type")
    if isinstance(t, list):
        value = dict(value)
        value["type"] = next((x for x in t if x != "null"), "string")
    return _orig_extract_field_type(self, key, value, model_name, root_schema)


_json_to_pydantic._JSONSchemaToPydantic._extract_field_type = _fold_null_union

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "target" / "release" / "mist-mcp.exe"
WAL_DIR = str(Path(__file__).resolve().parent / ".wal")


async def main() -> None:
    env = {"MIST_WAL_DIR": WAL_DIR}
    params = StdioServerParams(command=str(BIN), args=[], env=env)

    # 共享会话：stdio_client 拉起**一个** mist-mcp 子进程；factory 复用该会话。
    async with stdio_client(
        StdioServerParameters(command=str(BIN), args=[], env=env)
    ) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await mcp_server_tools(params, session=session)
            by_name = {t.name: t for t in tools}
            expected = {
                "authorize",
                "pay",
                "balance",
                "attest",
                "verify_receipt",
                "revocation_witness",
            }
            assert expected <= set(by_name), (
                f"MCP 工具不全: {sorted(expected - set(by_name))} 缺?"
            )

            async def call_tool(name: str, args: dict) -> tuple[bool, dict]:
                blocks = await by_name[name].run_json(args, CancellationToken())
                # 0.7.x run_json 返回 MCP 内容块 list（[TextContent{type,text}, …]），与
                # LangChain ainvoke 同形态；取 text 拼成 JSON 字符串再解析。
                if isinstance(blocks, list):
                    text = "".join(
                        b.get("text", "") if isinstance(b, dict) else getattr(b, "text", "")
                        for b in blocks
                    )
                else:
                    text = str(blocks)
                body = json.loads(text)
                return not body.get("error"), body

            await run_closed_loop(call_tool, log=lambda s: print(f"  [autogen] {s}"))


if __name__ == "__main__":
    asyncio.run(main())
