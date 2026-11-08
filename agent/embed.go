// Package agent embeds the agent scripts the server hands out.
package agent

import "embed"

//go:embed labwarden-agent.sh install.sh
var FS embed.FS
