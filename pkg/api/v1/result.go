// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	StatusFAIL     = "FAIL"
	StatusPASS     = "PASS"
	StatusSOFTFAIL = "SOFTFAIL"
)

// Assert reads the set's results and computes the finish date
// and set eval status.
func (rs *ResultSet) Assert() error {
	rs.DateEnd = timestamppb.Now()
	for _, r := range rs.Results {
		if r.Status == StatusFAIL {
			rs.Status = StatusFAIL
			return nil
		}
	}
	rs.Status = StatusPASS
	return nil
}

func (rs *ResultSet) MarshalJSON() ([]byte, error) {
	type Alias ResultSet
	var start, end string
	if rs.DateStart != nil {
		start = rs.DateStart.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	if rs.DateEnd != nil {
		end = rs.DateEnd.AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			DateStart string `json:"date_start"`
			DateEnd   string `json:"date_end"`
			*Alias
		}{
			DateStart: start,
			DateEnd:   end,
			Alias:     (*Alias)(rs),
		},
	)
}

func (r *Result) MarshalJSON() ([]byte, error) {
	type Alias Result
	var start, end string
	if r.DateStart != nil {
		start = r.DateStart.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	if r.DateEnd != nil {
		end = r.DateEnd.AsTime().Format("2006-01-02T15:04:05.000Z")
	}

	return json.Marshal(
		&struct {
			DateStart string `json:"date_start"`
			DateEnd   string `json:"date_end"`
			*Alias
		}{
			DateStart: start,
			DateEnd:   end,
			Alias:     (*Alias)(r),
		},
	)
}

func (er *EvalResult) MarshalJSON() ([]byte, error) {
	type Alias EvalResult
	var date string
	if er.Date != nil {
		date = er.Date.AsTime().Format("2006-01-02T15:04:05.000Z")
	}
	return json.Marshal(
		&struct {
			Date string `json:"date"`
			*Alias
		}{
			Date:  date,
			Alias: (*Alias)(er),
		},
	)
}
