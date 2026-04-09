package ffi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ffiResponse[T any] struct {
	OK    bool    `json:"ok"`
	Data  *T      `json:"data"`
	Error *string `json:"error"`
}

type updateResponse struct {
	Updated bool `json:"updated"`
}

type generateReportsResponse struct {
	Generated       bool   `json:"generated"`
	Vulnerabilities int    `json:"vulnerabilities"`
	PDFPath         string `json:"pdf_path"`
	XLSXPath        string `json:"xlsx_path"`
}

func testDatabaseURL() string {
	if value := os.Getenv("BDU_TEST_DATABASE_URL"); value != "" {
		return value
	}
	return "postgresql://bdu:bdu@localhost:5438/bdu"
}

func TestVersionReturnsString(t *testing.T) {
	version := Version()
	if version == "" {
		t.Fatal("expected non-empty version string")
	}
}

func TestUpdateReturnsJsonErrorForNilURL(t *testing.T) {
	raw := UpdateNil()
	if raw == "" {
		t.Fatal("expected non-empty JSON response")
	}

	var response ffiResponse[map[string]any]
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("expected valid JSON response, got %q: %v", raw, err)
	}

	if response.OK {
		t.Fatalf("expected failure response for nil postgres URL, got success: %s", raw)
	}

	if response.Error == nil || *response.Error == "" {
		t.Fatalf("expected error message in response: %s", raw)
	}

	if response.Data != nil {
		t.Fatalf("expected nil data on error response: %s", raw)
	}
}

func TestGenerateReportsViaFFI(t *testing.T) {
	databaseURL := testDatabaseURL()
	sbomPath := filepath.Join("..", "..", "extra", "cleaned_data.json")
	reportBasePath := filepath.Join("..", "..", "dist", "ffi_go_test_report")
	pdfPath := reportBasePath + ".pdf"
	texPath := reportBasePath + ".tex"
	xlsxPath := reportBasePath + ".xlsx"
	t.Cleanup(func() {
		_ = os.Remove(pdfPath)
		_ = os.Remove(texPath)
		_ = os.Remove(xlsxPath)
	})

	updateRaw := Update(databaseURL)
	if updateRaw == "" {
		t.Fatal("expected non-empty update response")
	}

	var updateResult ffiResponse[updateResponse]
	if err := json.Unmarshal([]byte(updateRaw), &updateResult); err != nil {
		t.Fatalf("expected valid update JSON response, got %q: %v", updateRaw, err)
	}
	if !updateResult.OK {
		t.Fatalf("expected update success, got: %s", updateRaw)
	}
	if updateResult.Data == nil || !updateResult.Data.Updated {
		t.Fatalf("expected updated=true in response, got: %s", updateRaw)
	}

	reportsRaw := GenerateReports(databaseURL, sbomPath, reportBasePath, true)
	if reportsRaw == "" {
		t.Fatal("expected non-empty generate_reports response")
	}

	var reportsResult ffiResponse[generateReportsResponse]
	if err := json.Unmarshal([]byte(reportsRaw), &reportsResult); err != nil {
		t.Fatalf("expected valid generate_reports JSON response, got %q: %v", reportsRaw, err)
	}
	if !reportsResult.OK {
		t.Fatalf("expected generate_reports success, got: %s", reportsRaw)
	}
	if reportsResult.Data == nil {
		t.Fatalf("expected generate_reports payload, got: %s", reportsRaw)
	}
	if !reportsResult.Data.Generated {
		t.Fatalf("expected generated=true, got: %s", reportsRaw)
	}
	if reportsResult.Data.Vulnerabilities == 0 {
		t.Fatalf("expected at least one vulnerability, got: %s", reportsRaw)
	}
	if reportsResult.Data.PDFPath != pdfPath {
		t.Fatalf("expected pdf_path=%q, got %q", pdfPath, reportsResult.Data.PDFPath)
	}
	if reportsResult.Data.XLSXPath != xlsxPath {
		t.Fatalf("expected xlsx_path=%q, got %q", xlsxPath, reportsResult.Data.XLSXPath)
	}
	if _, err := os.Stat(pdfPath); err != nil {
		t.Fatalf("expected generated PDF at %q: %v", pdfPath, err)
	}
	if _, err := os.Stat(xlsxPath); err != nil {
		t.Fatalf("expected generated XLSX at %q: %v", xlsxPath, err)
	}
}
