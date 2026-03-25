# `tripwire-server-go`

Official Tripwire Go server SDK.

`tripwire-server-go` exposes the customer-facing server APIs for:

- Sessions API
- Fingerprints API
- Teams API
- Team API key management
- sealed token verification

It does not include collect endpoints or internal scoring APIs.

## Installation

```bash
go get github.com/abxy-labs/tripwire-server-go
```

## Quick start

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

  log.Println(page.Items[0].ID)
}
```

Defaults:

- `base_url`: `https://api.tripwirejs.com`
- `secret_key`: `TRIPWIRE_SECRET_KEY`
- `timeout`: `30s`

## Development

The canonical cross-language server SDK spec lives in the Tripwire main repo under `sdk-spec/server/`.
This repo carries a synced copy in `spec/` for standalone testing and release workflows.
Official Tripwire Go server SDK
