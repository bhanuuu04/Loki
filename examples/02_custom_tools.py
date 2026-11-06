"""
Example 02: Creating Custom Tools
Demonstrates registering custom Python functions with the @tool decorator.
"""

import asyncio
from loki import LokiAgent, tool


# Define custom domain-specific tools with clear docstrings and type hints
@tool(name="currency_converter", description="Convert an amount between USD, EUR, and GBP.")
def convert_currency(amount: float, from_curr: str, to_curr: str) -> str:
    rates = {
        ("USD", "EUR"): 0.92,
        ("USD", "GBP"): 0.79,
        ("EUR", "USD"): 1.09,
        ("GBP", "USD"): 1.27,
    }
    key = (from_curr.upper(), to_curr.upper())
    if key in rates:
        converted = amount * rates[key]
        return f"{amount} {from_curr.upper()} = {converted:.2f} {to_curr.upper()}"
    return f"Exchange rate not found for {from_curr} to {to_curr}."


@tool(name="query_database", description="Simulate querying a customer database by customer ID.")
def query_db(customer_id: str) -> dict:
    mock_db = {
        "cust_101": {"name": "Alice Smith", "tier": "Enterprise", "balance": 1420.50},
        "cust_102": {"name": "Bob Jones", "tier": "Pro", "balance": 450.00},
    }
    return mock_db.get(customer_id, {"error": "Customer not found"})


async def main():
    # Instantiate agent with custom tools
    agent = LokiAgent(provider="mock", tools=[convert_currency, query_db])

    print("Registered Tools in Agent:")
    for t in agent.registry.list_tools():
        print(f" - {t.name}: {t.description}")

    # Inspect JSON schema generated for LLM tool calling
    print("\nOpenAI Schema for currency_converter:")
    import json
    schema = agent.registry.get("currency_converter").to_openai_schema()
    print(json.dumps(schema, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
