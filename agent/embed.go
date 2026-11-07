// Package agent embeds the agent scripts the server hands out.
package agent

import "embed"

//go:embed vulnx-agent.sh install.sh
var FS embed.FS
