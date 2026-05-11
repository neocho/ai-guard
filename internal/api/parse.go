package api

// Parsing helpers used to live here; they moved to internal/parse so the
// proxy can call them at capture time (eager parsing for scanner input).
// This file remains as a marker so future contributors don't try to
// duplicate the dispatch logic here.
