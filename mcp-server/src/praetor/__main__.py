import sys

from praetor.server import mcp


def main():
    # The external-tool / mobile / Frida lanes use asyncio.create_subprocess_exec,
    # which on Windows works only under the Proactor event loop. Python 3.8+ already
    # defaults to Proactor there, but a dependency could install the Selector policy
    # and break every subprocess call with NotImplementedError — pin Proactor so the
    # subprocess lanes stay reliable regardless. No-op on Linux/macOS.
    if sys.platform == "win32":
        import asyncio
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except AttributeError:
            pass
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
