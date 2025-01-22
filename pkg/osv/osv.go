package osv

import "github.com/puerco/ampel/pkg/osv/v1_6_7"

// The osv.Record type is always an alias to the latest defined record,
// however the parser should return the correct type
type Record = v1_6_7.Record

type RecordList []*Record
