package primitives

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"
)

func TestCollectErrorCountsCountsEachKind(t *testing.T) {
	provider := fakeDB(map[string]fakeRows{
		"FROM err_general_errors WHERE err_create_time >= now() - interval '24 hours'": {
			columns: []string{"a", "b", "c"},
			rows:    [][]driver.Value{{int64(6), int64(0), int64(41)}},
		},
	}, nil)
	db, err := provider()
	if err != nil {
		t.Fatal(err)
	}
	counts, ok := collectErrorCounts(context.Background(), db)
	if !ok {
		t.Fatal("the counts should read")
	}
	if counts["script_policy"] != int64(6) || counts["database"] != int64(0) || counts["exceptions"] != int64(41) {
		t.Errorf("each kind takes its own count, in the enum's order: %v", counts)
	}
	if len(counts) != len(logKindNames) {
		t.Errorf("one count per kind word: %v", counts)
	}
}

func TestCollectErrorCountsIsNotMeasuredWhenTheTableCannotBeRead(t *testing.T) {
	provider := fakeDB(nil, errors.New("relation does not exist"))
	db, err := provider()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := collectErrorCounts(context.Background(), db); ok {
		t.Error("an unreadable table is not measured, never zero errors")
	}
}
