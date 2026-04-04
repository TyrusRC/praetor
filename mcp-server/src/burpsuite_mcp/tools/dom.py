"""Tools for DOM structure analysis and JavaScript sink/source detection."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def analyze_dom(index: int) -> str:
        """Analyze HTML structure and JavaScript for security issues.
        Performs two types of analysis from the response body (no headless browser):

        HTML Analysis: Hidden fields, inline scripts, event handlers,
        iframes, HTML comments, meta tags, data attributes, framework detection.

        JS Sink/Source Analysis: Detects dangerous DOM manipulation patterns,
        user-input sources, prototype pollution, and potential source-to-sink flows.

        Args:
            index: Proxy history index of the response to analyze
        """
        data = await client.post("/api/analysis/dom", json={"index": index})
        if "error" in data:
            return f"Error: {data['error']}"

        lines = ["DOM & JavaScript Analysis:\n"]

        # HTML Analysis
        html = data.get("html_analysis", {})
        if html:
            lines.append("=== HTML Structure ===\n")

            frameworks = html.get("frameworks", [])
            if frameworks:
                lines.append(f"Frameworks: {', '.join(frameworks)}")
                lines.append("")

            hidden = html.get("hidden_fields", [])
            if hidden:
                lines.append(f"--- Hidden Fields ({len(hidden)}) ---")
                for f in hidden:
                    lines.append(f"  {f.get('name', '?')} = {f.get('value', '')}")
                lines.append("")

            meta = html.get("meta_tags", [])
            if meta:
                lines.append(f"--- Interesting Meta Tags ({len(meta)}) ---")
                for m in meta:
                    lines.append(f"  {m.get('name', '?')}: {m.get('content', '')}")
                lines.append("")

            data_attrs = html.get("data_attributes", [])
            if data_attrs:
                lines.append(f"--- Data Attributes ({len(data_attrs)}) ---")
                for d in data_attrs:
                    lines.append(f"  {d.get('name', '?')} = {d.get('value', '')}")
                lines.append("")

            comments = html.get("comments", [])
            if comments:
                lines.append(f"--- HTML Comments ({len(comments)}) ---")
                for c in comments[:10]:
                    content = c.get("content", "").strip()[:150]
                    lines.append(f"  <!-- {content} -->")
                lines.append("")

            event_handlers = html.get("event_handlers", [])
            if event_handlers:
                lines.append(f"--- Event Handlers ({len(event_handlers)}) ---")
                for e in event_handlers[:20]:
                    lines.append(f"  {e.get('event', '?')}: {e.get('handler', '')}")
                lines.append("")

            iframes = html.get("iframes", [])
            if iframes:
                lines.append(f"--- Iframes ({len(iframes)}) ---")
                for f in iframes:
                    lines.append(f"  src: {f.get('src', '?')}")
                lines.append("")

            scripts = html.get("inline_scripts", [])
            if scripts:
                lines.append(f"--- Inline Scripts ({len(scripts)}) ---")
                for s in scripts[:5]:
                    content = s.get("content", "")[:200]
                    lines.append(f"  [{s.get('line', '?')}] {content}")
                lines.append("")

        # JS Analysis
        js = data.get("js_analysis", {})
        if js:
            lines.append("=== JavaScript Security Analysis ===\n")

            sinks = js.get("sinks", [])
            if sinks:
                lines.append(f"--- Sinks ({js.get('total_sinks', len(sinks))}) ---")
                for s in sinks:
                    lines.append(f"  [{s.get('risk', '?')}] {s.get('type', '?')}")
                    lines.append(f"    {s.get('context', '')}")
                lines.append("")

            sources = js.get("sources", [])
            if sources:
                lines.append(f"--- Sources ({js.get('total_sources', len(sources))}) ---")
                for s in sources:
                    lines.append(f"  [{s.get('risk', '?')}] {s.get('type', '?')}")
                    lines.append(f"    {s.get('context', '')}")
                lines.append("")

            proto = js.get("prototype_pollution", [])
            if proto:
                lines.append(f"--- Prototype Pollution ({len(proto)}) ---")
                for p in proto:
                    lines.append(f"  [{p.get('risk', '?')}] {p.get('pattern', '?')}")
                    lines.append(f"    {p.get('context', '')}")
                lines.append("")

            dangerous = js.get("dangerous_patterns", [])
            if dangerous:
                lines.append(f"--- Dangerous Patterns ({len(dangerous)}) ---")
                for d in dangerous:
                    lines.append(f"  [{d.get('risk', '?')}] {d.get('type', '?')}")
                    lines.append(f"    {d.get('context', '')}")
                lines.append("")

            flows = js.get("potential_flows", [])
            if flows:
                lines.append(f"--- Potential Source->Sink Flows ({len(flows)}) ---")
                for f in flows:
                    lines.append(f"  {f.get('source', '?')} -> {f.get('sink', '?')}")
                    lines.append(f"    {f.get('description', '')}")
                lines.append("")

        if len(lines) <= 2:
            return "No significant HTML/JS security findings in this response."

        return "\n".join(lines)
