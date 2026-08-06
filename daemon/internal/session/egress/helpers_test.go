package egress

import (
	"io"
	"log/slog"
)

// discardLogger silences controller logs during tests.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
