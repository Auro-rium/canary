# Agent Canary GitHub Action

Run Canary against a registered preview agent on every pull request:

```yaml
- name: Agent Canary
  uses: Auro-rium/canary/action@main
  with:
    api-url: ${{ secrets.CANARY_API_URL }}
    api-token: ${{ secrets.CANARY_API_TOKEN }}
    project-id: ${{ secrets.CANARY_PROJECT_ID }}
```

The action starts a release evaluation for the current commit, waits for the
existing LangGraph red-team campaign to finish, writes the baseline comparison
to the GitHub job summary, and fails the check only when Canary returns
`block`.
