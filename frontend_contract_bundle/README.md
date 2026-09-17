# Fable frontend contract bundle

Contract version: 2.0.0.

These are sanitized, synthetic recording fixtures captured through authenticated
FastAPI routes. They contain no bearer credentials and no real people or organizations.
Opaque entity references and response-action IDs belong to this capture.

Regenerate from the repository root with:

    python frontend_contract_bundle/generate.py

The generator creates an in-memory database, seeds the four synthetic scenarios, and
captures this sequence:

1. Export OpenAPI and its component schemas.
2. Read the authenticated case list.
3. Read Priya, Devraj, Arjun, and Neha case details.
4. Read Arjun's NetworkX evidence graph.
5. Preview a scoped Devraj download rate limit without mutation.
6. Request a high-impact Devraj device isolation.
7. Approve it as a different response approver.
8. Execute and verify it in the sandbox.
9. Roll it back and verify restoration.
10. Capture Arjun's immutable original/current assessment views.
11. Capture the final simulated enforcement state as an admin.

openapi.json is the final route contract. typescript-friendly-schema.json contains
the OpenAPI component schemas as a convenient frontend code-generation input.
