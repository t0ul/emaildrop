package main

import (
	"github.com/t0ul/emaildrop/pkg/datastore"
	"github.com/t0ul/emaildrop/pkg/server"
)

// eventProjection adapts the datastore events table to server.EventStore: it is the
// DB-backed calendar projection the view serves from, converting between the server's
// Event and the datastore's EventRow. The signed .ics outbox stays the source of
// truth; this is rebuilt from it whenever the outbox changes.
type eventProjection struct{ inv *datastore.Store }

func (e eventProjection) ReplaceEvents(fp string, evs []server.Event) error {
	rows := make([]datastore.EventRow, len(evs))
	for i, ev := range evs {
		rows[i] = datastore.EventRow{
			Title: ev.Title, Start: ev.Start, End: ev.End, Location: ev.Location,
			AllDay: ev.AllDay, HasReminder: ev.HasReminder, Signed: ev.Signed,
			File: ev.File, Kind: ev.Kind, Due: ev.Due, URL: ev.URL,
		}
	}
	return e.inv.ReplaceEvents(fp, rows)
}

func (e eventProjection) LoadEvents() (string, []server.Event, error) {
	fp, rows, err := e.inv.LoadEvents()
	if err != nil {
		return "", nil, err
	}
	evs := make([]server.Event, len(rows))
	for i, r := range rows {
		evs[i] = server.Event{
			Title: r.Title, Start: r.Start, End: r.End, Location: r.Location,
			AllDay: r.AllDay, HasReminder: r.HasReminder, Signed: r.Signed,
			File: r.File, Kind: r.Kind, Due: r.Due, URL: r.URL,
		}
	}
	return fp, evs, nil
}

// summaryProjection adapts the datastore summaries table to server.SummaryStore (the
// DB-backed projection of the per-email sidecars the Tasks/digest/Directory/Review
// views serve from). The .summary.json files stay the source of truth.
type summaryProjection struct{ inv *datastore.Store }

func (p summaryProjection) ReplaceSummaries(fp string, rows []server.SummaryRow) error {
	dr := make([]datastore.SummaryRow, len(rows))
	for i, r := range rows {
		dr[i] = datastore.SummaryRow{File: r.File, JSON: r.JSON}
	}
	return p.inv.ReplaceSummaries(fp, dr)
}

func (p summaryProjection) LoadSummaries() (string, []server.SummaryRow, error) {
	fp, rows, err := p.inv.LoadSummaries()
	if err != nil {
		return "", nil, err
	}
	sr := make([]server.SummaryRow, len(rows))
	for i, r := range rows {
		sr[i] = server.SummaryRow{File: r.File, JSON: r.JSON}
	}
	return fp, sr, nil
}

// itemProjection adapts the datastore items table to server.ItemStore: the DB-backed
// DEDUPED item projection the Tasks tab and mini-calendar serve from.
type itemProjection struct{ inv *datastore.Store }

func (p itemProjection) ReplaceItems(fp string, rows []server.PersistedItem) error {
	dr := make([]datastore.PersistedItem, len(rows))
	for i, r := range rows {
		dr[i] = datastore.PersistedItem{File: r.File, Index: r.Index, JSON: r.JSON}
	}
	return p.inv.ReplaceItems(fp, dr)
}

func (p itemProjection) LoadItems() (string, []server.PersistedItem, error) {
	fp, rows, err := p.inv.LoadItems()
	if err != nil {
		return "", nil, err
	}
	sr := make([]server.PersistedItem, len(rows))
	for i, r := range rows {
		sr[i] = server.PersistedItem{File: r.File, Index: r.Index, JSON: r.JSON}
	}
	return fp, sr, nil
}
