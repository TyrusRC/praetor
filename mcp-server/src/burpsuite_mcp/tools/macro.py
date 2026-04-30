"""Reusable request macros — recorded sequences with variable extraction and interpolation."""

from mcp.server.fastmcp import FastMCP

from burpsuite_mcp import client


def register(mcp: FastMCP):

    @mcp.tool()
    async def create_macro(
        name: str,
        description: str,
        steps: list[dict],
    ) -> str:
        """Create a reusable request macro with variable extraction between steps.

        Args:
            name: Unique macro name
            description: What this macro does
            steps: Ordered list of request step dicts with optional extract rules
        """
        payload = {
            "name": name,
            "description": description,
            "steps": steps,
        }
        data = await client.post("/api/macro/create", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        return (
            f"Macro '{data.get('name', name)}' created with {data.get('steps', len(steps))} steps.\n"
            f"Run it with: run_macro('{name}')"
        )

    @mcp.tool()
    async def run_macro(
        name: str,
        variables: dict | None = None,
    ) -> str:
        """Execute a macro and return extracted variables and step results.

        Args:
            name: Name of the macro to execute
            variables: Optional initial variables for {{name}} interpolation
        """
        payload: dict = {"name": name}
        if variables:
            payload["variables"] = variables

        data = await client.post("/api/macro/run", json=payload)
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [f"Macro '{name}': {data.get('steps_executed', 0)} steps executed\n"]

        for step in data.get("results", []):
            status = step.get("status", 0)
            url = step.get("url", "")
            method = step.get("method", "")
            line = f"  Step {step.get('step')}: {method} {url} -> {status}"
            if step.get("error"):
                line += f" ERROR: {step['error']}"
            if step.get("response_length") is not None:
                line += f" ({step['response_length']} bytes)"
            lines.append(line)

        extracted = data.get("variables", {})
        if extracted:
            lines.append(f"\nExtracted variables ({len(extracted)}):")
            for k, v in extracted.items():
                display = v if len(str(v)) < 100 else str(v)[:100] + "..."
                lines.append(f"  {k} = {display}")

        return "\n".join(lines)

    @mcp.tool()
    async def list_macros() -> str:
        """List all defined macros with names, descriptions, and step counts."""
        data = await client.get("/api/macro/list")
        if "error" in data:
            return f"Error: {data['error']}"

        macro_list = data.get("macros", [])
        if not macro_list:
            return "No macros defined. Use create_macro() to create one."

        lines = [f"Macros ({data.get('total_count', len(macro_list))}):\n"]
        for m in macro_list:
            lines.append(f"  {m['name']} ({m.get('steps', 0)} steps)")
            if m.get("description"):
                lines.append(f"    {m['description']}")
        return "\n".join(lines)

    @mcp.tool()
    async def get_macro(name: str) -> str:
        """Get full definition of a macro including all steps and extraction rules.

        Args:
            name: Name of the macro to retrieve
        """
        data = await client.get(f"/api/macro/{name}")
        if "error" in data:
            return f"Error: {data['error']}"

        lines = [
            f"Macro: {data.get('name', name)}",
            f"Description: {data.get('description', '')}",
            "",
        ]

        steps = data.get("steps", [])
        for i, step in enumerate(steps, 1):
            lines.append(f"Step {i}: {step.get('method', 'GET')} {step.get('url', '')}")
            if step.get("headers"):
                for k, v in step["headers"].items():
                    lines.append(f"  Header: {k}: {v}")
            if step.get("body"):
                body = step["body"]
                if len(body) > 200:
                    body = body[:200] + "..."
                lines.append(f"  Body: {body}")
            if step.get("extract"):
                for rule in step["extract"]:
                    lines.append(
                        f"  Extract: {rule.get('name')} from {rule.get('source', 'body')} "
                        f"pattern='{rule.get('pattern')}' group={rule.get('group', 1)}"
                    )
            lines.append("")

        return "\n".join(lines)

    @mcp.tool()
    async def delete_macro(name: str) -> str:
        """Delete a macro by name.

        Args:
            name: Name of the macro to delete
        """
        data = await client.delete(f"/api/macro/{name}")
        if "error" in data:
            return f"Error: {data['error']}"
        return data.get("message", f"Macro '{name}' deleted.")
