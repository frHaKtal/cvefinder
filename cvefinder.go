package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
	"golang.org/x/sync/errgroup"
)

const (
	nvdAPI       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	vulnersAPI   = "https://vulners.com/api/v3/search/lucene/"
	exploitDBURL = "https://www.exploit-db.com/search"
)

var (
	severityColors = map[string]*color.Color{
		"critical": color.New(color.FgRed, color.Bold),
		"high":     color.New(color.FgHiRed),
		"medium":   color.New(color.FgYellow),
		"low":      color.New(color.FgGreen),
		"info":     color.New(color.FgCyan),
		"unknown":  color.New(color.FgHiBlack),
	}

	cache        = sync.Map{}
	exploitCache = sync.Map{}
	httpClient   *http.Client
	reTech       = regexp.MustCompile(`^([^:]+):\s*(.+)$`)

	// === API KEY HARDCODÉE (optionnel) ===
	apiKey = "" // ← Mets ta clé en clair ICI si tu veux (ex: "sk_abc123...") ou laisse vide pour env var
)

type CVE struct {
	ID        string
	Desc      string
	Score     string
	Severity  string
	Exploits  []Exploit
}

type Exploit struct{ Title, URL string }

type Result struct {
	URL   string
	Tech  map[string]string
	Vulns []CVE
}

// === INIT ===
func init() {
	httpClient = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:       200,
			MaxConnsPerHost:     100,
			ForceAttemptHTTP2:  true,
		},
	}
}

// === BANNER ===
func printBanner() {
        banner := `
  ______     _______ _____ ___ _   _ ____  _____ ____
 / ___\ \   / / ____|  ___|_ _| \ | |  _ \| ____|  _ \
| |    \ \ / /|  _| | |_   | ||  \| | | | |  _| | |_) |
| |___  \ V / | |___|  _|  | || |\  | |_| | |___|  _ <
 \____|  \_/  |_____|_|   |___|_| \_|____/|_____|_| \_\ v2.0

       Tech + NVD + Exploit‑DB or Tech + Vulners
                     by _frHaKtal_
`
        color.New(color.FgCyan, color.Bold).Println(banner)}


// === HELP ===
func printHelp() {
	help := `
USAGE:
  cvefinder [OPTIONS] < input.txt

SOURCE:
  -nvd          Use NVD + Exploit-DB (100% free, unlimited)
  -vulners      Use Vulners:
                  • With API key (env VULNERS_API_KEY or hardcoded) → full results + exploits
                  • Without key → public results only (still better than NVD)

  Default: Vulners if key, else NVD

OPTIONS:
  -f string     Input file
  -c int        Concurrency (default 50)
  -all-tech     Show all techs
  --help, -h    Show help

EXAMPLES:
  export VULNERS_API_KEY="sk_abc123"
  echo "http://target" | cvefinder -vulners
  cvefinder -f targets.txt -nvd -c 200 -all-tech
`
	color.New(color.FgCyan, color.Bold).Println(help)
	os.Exit(0)
}

// === HTTP GET ===
func fetch(u string) ([]byte, error) {
	resp, err := httpClient.Get(u)
	if err != nil || resp.StatusCode != 200 {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// === NVD ===
func getCVEsFromNVD(queries []string) map[string][]CVE {
	results := make(map[string][]CVE)
	var eg errgroup.Group
	var mu sync.Mutex

	for _, q := range queries {
		if val, ok := cache.Load("nvd:"+q); ok {
			results[q] = val.([]CVE)
			continue
		}
		currentQ := q
		eg.Go(func() error {
			params := url.Values{}
			params.Set("keywordSearch", currentQ)
			params.Set("resultsPerPage", "50")
			data, err := fetch(nvdAPI + "?" + params.Encode())
			if err != nil { return err }

			var res struct {
				Vulnerabilities []struct {
					CVE struct {
						ID           string `json:"id"`
						Descriptions []struct{ Value string `json:"value"` } `json:"descriptions"`
						Metrics      struct {
							CVSS31 []struct {
								CVSS struct {
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
						} `json:"metrics"`
					} `json:"cve"`
				} `json:"vulnerabilities"`
			}
			if json.Unmarshal(data, &res) != nil { return nil }

			cves := []CVE{}
			tech := strings.Split(currentQ, " ")[0]
			for _, v := range res.Vulnerabilities {
				c := v.CVE
				score, sev := "N/A", "unknown"
				if len(c.Metrics.CVSS31) > 0 {
					score = fmt.Sprintf("%.1f", c.Metrics.CVSS31[0].CVSS.BaseScore)
					sev = strings.ToLower(c.Metrics.CVSS31[0].CVSS.BaseSeverity)
				}
				desc := ""
				if len(c.Descriptions) > 0 { desc = c.Descriptions[0].Value }
				if strings.Contains(strings.ToLower(desc), tech) {
					cves = append(cves, CVE{ID: c.ID, Desc: desc, Score: score, Severity: sev})
				}
			}
			mu.Lock()
			results[currentQ] = cves
			cache.Store("nvd:"+currentQ, cves)
			mu.Unlock()
			return nil
		})
	}
	eg.Wait()
	return results
}

// === VULNERS (AVEC OU SANS KEY) ===
func getCVEsFromVulners(queries []string, apiKey string) map[string][]CVE {
	results := make(map[string][]CVE)
	var eg errgroup.Group
	var mu sync.Mutex

	for _, q := range queries {
		cacheKey := "vulners"
		if apiKey != "" {
			cacheKey += ":key"
		}
		cacheKey += ":" + q

		if val, ok := cache.Load(cacheKey); ok {
			results[q] = val.([]CVE)
			continue
		}

		currentQ := q
		eg.Go(func() error {
			parts := strings.Split(currentQ, " ")
			tech, ver := parts[0], ""
			if len(parts) > 1 { ver = parts[1] }

			lucene := fmt.Sprintf(`(affectedPackage.packageName:%s*) OR (title:%s* AND version:%s*) OR (cpe:2.3:*:*:*:%s:*:*:*:*:*:*) bulletinFamily:cve`, tech, tech, ver, ver)
			postData := map[string]interface{}{"query": strings.TrimSpace(lucene), "size": 30}
			jsonPost, _ := json.Marshal(postData)

			req, _ := http.NewRequest("POST", vulnersAPI, strings.NewReader(string(jsonPost)))
			req.Header.Set("Content-Type", "application/json")

			if apiKey != "" {
				req.Header.Set("X-Api-Key", apiKey)
			}

			resp, err := httpClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				nvdResults := getCVEsFromNVD([]string{currentQ})
				mu.Lock()
				results[currentQ] = nvdResults[currentQ]
				cache.Store(cacheKey, nvdResults[currentQ])
				mu.Unlock()
				return nil
			}
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)

			var res struct {
				Result struct {
					Search []struct {
						Id       string `json:"_id"`
						Title    string `json:"title"`
						Cvss     struct{ Score float64 `json:"score"` } `json:"cvss"`
						Severity string `json:"severity"`
						Exploit  []struct{ Url string `json:"url"` } `json:"exploit"`
					} `json:"search"`
				} `json:"result"`
			}
			if json.Unmarshal(data, &res) != nil || len(res.Result.Search) == 0 {
				nvdResults := getCVEsFromNVD([]string{currentQ})
				mu.Lock()
				results[currentQ] = nvdResults[currentQ]
				cache.Store(cacheKey, nvdResults[currentQ])
				mu.Unlock()
				return nil
			}

			cves := []CVE{}
			for _, v := range res.Result.Search {
				sev := strings.ToLower(v.Severity)
				exploits := []Exploit{}
				if apiKey != "" {
					for _, e := range v.Exploit {
						if e.Url == "" { continue }
						ext := strings.ToUpper(strings.TrimPrefix(filepath.Ext(e.Url), "."))
						if ext == "" { ext = "LINK" }
						exploits = append(exploits, Exploit{Title: "Vulners [" + ext + "]", URL: e.Url})
					}
				}
				score := "N/A"
				if v.Cvss.Score > 0 {
					score = fmt.Sprintf("%.1f", v.Cvss.Score)
				}
				cves = append(cves, CVE{
					ID: v.Id, Desc: v.Title, Score: score,
					Severity: sev, Exploits: exploits,
				})
			}
			mu.Lock()
			results[currentQ] = cves
			cache.Store(cacheKey, cves)
			mu.Unlock()
			return nil
		})
	}
	eg.Wait()
	return results
}

// === EXPLOIT-DB ===
func getExploitsFromEDB(cveID string) []Exploit {
	if val, ok := exploitCache.Load(cveID); ok { return val.([]Exploit) }
	cveNum := strings.TrimPrefix(cveID, "CVE-")
	data, err := fetch(exploitDBURL + "?cve=" + cveNum)
	if err != nil { return nil }

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(data)))
	if err != nil { return nil }

	exploits := []Exploit{}
	doc.Find("#exploits-table tbody tr").EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= 5 { return false }
		a := s.Find("td").Eq(4).Find("a")
		href, _ := a.Attr("href")
		title := strings.TrimSpace(a.Text())
		if href != "" && title != "" {
			exploits = append(exploits, Exploit{Title: title, URL: "https://www.exploit-db.com" + href})
		}
		return true
	})
	exploitCache.Store(cveID, exploits)
	return exploits
}

// === HTTPX ===
func runHttpxBatch(urls []string) []map[string]string {
	if len(urls) == 1 { return []map[string]string{runHttpx(urls[0])} }
	tmp, _ := os.CreateTemp("", "httpx-*.txt")
	for _, u := range urls { fmt.Fprintln(tmp, u) }
	tmp.Close()
	defer os.Remove(tmp.Name())

	cmd := exec.Command("httpx", "-l", tmp.Name(), "--tech-detect", "-json", "--silent")
	out, _ := cmd.Output()

	techs := []map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if line == "" { continue }
		var data struct{ Tech []string `json:"tech"` }
		if json.Unmarshal([]byte(line), &data) != nil { continue }
		tech := map[string]string{}
		for _, t := range data.Tech {
			if m := reTech.FindStringSubmatch(t); len(m) == 3 {
				name := strings.ToLower(strings.TrimSpace(m[1]))
				ver := strings.TrimSpace(m[2])
				if ver != "unknown" && ver != "" { tech[name] = ver }
			}
		}
		techs = append(techs, tech)
	}
	return techs
}

func runHttpx(u string) map[string]string {
	cmd := exec.Command("httpx", "-u", u, "--tech-detect", "-json", "--silent")
	out, _ := cmd.Output()
	var data struct{ Tech []string `json:"tech"` }
	if json.Unmarshal(out, &data) != nil { return nil }
	tech := map[string]string{}
	for _, t := range data.Tech {
		if m := reTech.FindStringSubmatch(t); len(m) == 3 {
			name := strings.ToLower(strings.TrimSpace(m[1]))
			ver := strings.TrimSpace(m[2])
			if ver != "unknown" && ver != "" { tech[name] = ver }
		}
	}
	return tech
}

// === SCAN ===
func scanURLFast(urlStr string, tech map[string]string, source, apiKey string) Result {
	res := Result{URL: urlStr, Tech: tech}
	queries := []string{}
	for t, v := range tech { queries = append(queries, t+" "+v) }

	var cveMap map[string][]CVE
	if source == "vulners" {
		cveMap = getCVEsFromVulners(queries, apiKey)
	} else {
		cveMap = getCVEsFromNVD(queries)
	}

	cveIDs := []string{}
	for _, cves := range cveMap {
		for _, cve := range cves {
			res.Vulns = append(res.Vulns, cve)
			cveIDs = append(cveIDs, cve.ID)
		}
	}

	// Exploits
	if source == "nvd" {
		var eg errgroup.Group
		for i := range res.Vulns {
			idx := i
			eg.Go(func() error {
				res.Vulns[idx].Exploits = getExploitsFromEDB(res.Vulns[idx].ID)
				return nil
			})
		}
		eg.Wait()
	}
	// Vulners already has exploits

	return res
}

// === PRINT ===
func printResults(results []Result, allTech bool) {
	mag := color.New(color.FgMagenta)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite)

	type TechVulns struct{ Name, Ver string; CVEs []CVE }

	for _, r := range results {
		mag.Println(strings.Repeat("=", 60))
		cyan.Print("Target: ")
		color.New(color.Bold).Println(r.URL)
		mag.Println(strings.Repeat("=", 60))

		if len(r.Tech) == 0 { color.Yellow(" No tech."); continue }

		var groups []TechVulns
		for name, ver := range r.Tech {
			var cves []CVE
			lower := strings.ToLower(name)
			for _, v := range r.Vulns {
				if strings.Contains(strings.ToLower(v.Desc), lower) ||
					strings.Contains(strings.ToLower(v.Desc), strings.TrimSuffix(lower, " server")) {
					cves = append(cves, v)
				}
			}
			if allTech || len(cves) > 0 {
				groups = append(groups, TechVulns{Name: strings.Title(name), Ver: ver, CVEs: cves})
			}
		}

		for _, g := range groups {
			color.Green("[+] Detected")
			white.Print(g.Name)
			if g.Ver != "" { color.New(color.FgHiWhite).Print(" v" + g.Ver) }
			fmt.Println()

			if len(g.CVEs) == 0 {
				color.New(color.FgHiBlack).Println("   No relevant CVE.")
				continue
			}

			for _, v := range g.CVEs {
				col := severityColors[v.Severity]
				if col == nil { col = severityColors["unknown"] }
				score := v.Score
				if score == "N/A" { score = "?.?" }
				col.Printf(" → %s [%s] %s\n", v.ID, strings.ToUpper(v.Severity), score)
				desc := regexp.MustCompile(`\s+`).ReplaceAllString(v.Desc, " ")
				if len(desc) > 180 { desc = desc[:180] + "..." }
				color.New(color.FgHiBlack).Println("   " + desc)

				if len(v.Exploits) > 0 {
					for _, e := range v.Exploits {
						color.Red(" EXP: " + e.Title + " ")
						color.Blue(e.URL)
						fmt.Println()
					}
				} else {
					color.New(color.FgHiBlack).Println("   No public exploit.")
				}
			}
			fmt.Println()
		}
	}
}

// === MAIN ===
func main() {
	printBanner()

	var fileFlag string
	var conc int
	var allTech bool
	var useNVD, useVulners bool

	flag.StringVar(&fileFlag, "f", "", "Input file")
	flag.IntVar(&conc, "c", 50, "Concurrency")
	flag.BoolVar(&allTech, "all-tech", false, "Show all techs")
	flag.BoolVar(&useNVD, "nvd", false, "Use NVD + Exploit-DB (free)")
	flag.BoolVar(&useVulners, "vulners", false, "Use Vulners (API key optional)")

	for _, a := range os.Args {
		if a == "--help" || a == "-h" { printHelp() }
	}
	flag.Parse()

	// === API KEY ENV VAR ===
	if apiKey == "" {
		apiKey = os.Getenv("VULNERS_API_KEY")
	}

	// === SOURCE LOGIC ===
	source := ""
	if useVulners {
		source = "vulners"
	} else if useNVD {
		source = "nvd"
	} else {
		if apiKey != "" {
			source = "vulners"
		} else {
			source = "nvd"
		}
	}

	// Vulners sans clé → OK, public mode
	if source == "vulners" && apiKey == "" {
		color.Yellow("Vulners (no API key) → limited results, no private exploits")
	}

	color.Cyan("Source: %s\n", strings.ToUpper(source))

	if _, err := exec.LookPath("httpx"); err != nil {
		color.Red("httpx not found: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
		os.Exit(1)
	}

	urls := []string{}
	if fileFlag != "" {
		f, _ := os.Open(fileFlag)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") { urls = append(urls, l) }
		}
		f.Close()
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") { urls = append(urls, l) }
		}
	}

	if len(urls) == 0 { os.Exit(0) }

	for i := range urls {
		if !strings.HasPrefix(urls[i], "http") { urls[i] = "http://" + urls[i] }
	}

	techs := runHttpxBatch(urls)
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	results := make([]Result, len(urls))

	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string, t map[string]string) {
			defer wg.Done()
			sem <- struct{}{}
			results[i] = scanURLFast(u, t, source, apiKey)
			<-sem
		}(i, u, techs[i])
	}
	wg.Wait()

	printResults(results, allTech)
}
