# Tripwire Go Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Go 1.22+](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Go library provides convenient access to the Tripwire API from Go services and applications. It includes a context-aware client for Sessions, visitor fingerprints, Teams, Team API key management, and sealed token verification.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- iterator-style helpers for cursor-based pagination
- structured API errors and built-in sealed token verification

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the module. If you just want to use it, run:

```bash
go get github.com/abxy-labs/tripwire-server-go
```

## Requirements

- Go 1.22+

## Usage

The library needs to be configured with your account's secret key. Set `TRIPWIRE_SECRET_KEY` in your environment or pass it explicitly when building a client:

```go
package main

import (
  "context"
  "log"

  tripwire "github.com/abxy-labs/tripwire-server-go"
)

func main() {
  client, err := tripwire.NewClient(tripwire.WithSecretKey("sk_live_..."))
  if err != nil {
    log.Fatal(err)
  }

  page, err := client.Sessions.List(context.Background(), tripwire.SessionListParams{
    Verdict: "bot",
    Limit:   25,
  })
  if err != nil {
    log.Fatal(err)
  }

  session, err := client.Sessions.Get(context.Background(), "sid_0123456789abcdefghjkmnpqrs")
  if err != nil {
    log.Fatal(err)
  }

  log.Println(page.Items[0].ID, session.Decision.AutomationStatus, session.Highlights[0].Summary)
}
```

### Sealed token verification

```go
result := tripwire.SafeVerifyTripwireToken(sealedToken, "sk_live_...")
if !result.OK {
  log.Fatal(result.Error)
}

log.Println(result.Data.Decision.Verdict, result.Data.Decision.RiskScore)
```

### Pagination

```go
err := client.Sessions.Iter(context.Background(), tripwire.SessionListParams{Search: "signup"}, func(session tripwire.SessionSummary) error {
  log.Println(session.ID, session.LatestDecision.Verdict)
  return nil
})
if err != nil {
  log.Fatal(err)
}
```

### Visitor fingerprints

```go
fingerprint, err := client.Fingerprints.Get(context.Background(), "vid_0123456789abcdefghjkmnpqrs")
if err != nil {
  log.Fatal(err)
}

log.Println(fingerprint.ID)
```

### Teams

```go
team, err := client.Teams.Get(context.Background(), "team_0123456789abcdefghjkmnpqrs")
if err != nil {
  log.Fatal(err)
}

updated, err := client.Teams.Update(context.Background(), "team_0123456789abcdefghjkmnpqrs", tripwire.UpdateTeamParams{
  Name: "New Name",
})
if err != nil {
  log.Fatal(err)
}

_, _ = team, updated
```

### Team API keys

```go
created, err := client.Teams.APIKeys.Create(
  context.Background(),
  "team_0123456789abcdefghjkmnpqrs",
  tripwire.CreateAPIKeyParams{Name: "Production", Environment: "live"},
)
if err != nil {
  log.Fatal(err)
}

_, err = client.Teams.APIKeys.Revoke(context.Background(), "team_0123456789abcdefghjkmnpqrs", created.ID)
if err != nil {
  log.Fatal(err)
}
```

### Error handling

```go
_, err := client.Sessions.List(context.Background(), tripwire.SessionListParams{Limit: 999})
if apiErr, ok := err.(*tripwire.APIError); ok {
  log.Println(apiErr.Status, apiErr.Code, apiErr.Message)
}
```

## Support

If you need help integrating Tripwire, start with [tripwirejs.com/docs](https://tripwirejs.com/docs).
