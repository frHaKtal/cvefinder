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
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/fatih/color"
)

const (
	nvdAPI       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	exploitDBURL = "https://www.exploit-db.com/search"
)

var severityColors = map[string]*color.Color{
	"critical": color.New(color.FgRed),
	"high":     color.New(color.FgHiRed),
	"medium":   color.New(color.FgYellow),
	"low":      color.New(color.FgGreen),
	"info":     color.New(color.FgCyan),
	"unknown":  color.New(color.FgHiBlack),
}

type CVE struct {
	ID        string
	Desc      string
	Score     string
	Severity  string
	Exploits  []Exploit
}

type Exploit struct {
	Title string
	URL   string
}

type Result struct {
	URL   string
	Tech  map[string]string
	Vulns []CVE
}

func printBanner() {

        banner := `
  ______     _______ _____ ___ _   _ ____  _____ ____
 / ___\ \   / / ____|  ___|_ _| \ | |  _ \| ____|  _ \
| |    \ \ / /|  _| | |_   | ||  \| | | | |  _| | |_) |
| |___  \ V / | |___|  _|  | || |\  | |_| | |___|  _ <
 \____|  \_/  |_____|_|   |___|_| \_|____/|_____|_| \_\

                Tech + NVD + Exploit‑DB
                     by _frHaKtal_
`
        color.New(color.FgCyan, color.Bold).Println(banner)
}


func fetch(urlStr string, params map[string]string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	u, _ := url.Parse(urlStr)
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	resp, err := client.Get(u.String())
	if err != nil || resp.StatusCode != 200 {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func getCVEs(tech, ver string) []CVE {
	if ver == "" {
		return nil
	}
	params := map[string]string{"keywordSearch": tech + " " + ver, "resultsPerPage": "20"}
	data, _ := fetch(nvdAPI, params)
	var res struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Descriptions []struct {
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics struct {
					CVSS31 []struct {
						CVSS struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSS2 []struct {
						CVSS struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV2"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	json.Unmarshal(data, &res)
	cves := []CVE{}
	for _, v := range res.Vulnerabilities {
		c := v.CVE
		score := "N/A"
		sev := "unknown"
		if len(c.Metrics.CVSS31) > 0 {
			score = fmt.Sprintf("%.1f", c.Metrics.CVSS31[0].CVSS.BaseScore)
			sev = strings.ToLower(c.Metrics.CVSS31[0].CVSS.BaseSeverity)
		} else if len(c.Metrics.CVSS2) > 0 {
			score = fmt.Sprintf("%.1f", c.Metrics.CVSS2[0].CVSS.BaseScore)
			sev = strings.ToLower(c.Metrics.CVSS2[0].CVSS.BaseSeverity)
		}
		desc := ""
		if len(c.Descriptions) > 0 {
			desc = c.Descriptions[0].Value
		}
		if strings.Contains(strings.ToLower(desc), ver) {
			cves = append(cves, CVE{ID: c.ID, Desc: desc, Score: score, Severity: sev})
		}
	}
	return cves
}


func getExploits(cve string) []Exploit {
	parts := strings.Split(cve, "-")
	if len(parts) < 3 {
		return nil
	}
	cveID := parts[2]
	params := map[string]string{"cve": cveID}
	htmlBytes, _ := fetch(exploitDBURL, params)
	if htmlBytes == nil {
		return nil
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(htmlBytes)))
	if err != nil {
		return nil
	}
	exploits := []Exploit{}
	sel := doc.Find("#exploits-table tbody tr")
	count := sel.Length()
	if count == 0 {
		return nil
	}
	limit := 3
	if count < 3 {
		limit = count
	}
	sel.EachWithBreak(func(i int, s *goquery.Selection) bool {
		if i >= limit {
			return false
		}
		tds := s.Find("td")
		if tds.Length() < 5 {
			return true
		}
		a := tds.Eq(4).Find("a")
		href, _ := a.Attr("href")
		if href == "" {
			return true
		}
		exploits = append(exploits, Exploit{
			Title: strings.TrimSpace(a.Text()),
			URL:   "https://www.exploit-db.com" + href,
		})
		return true
	})
	return exploits
}
func runHttpx(urlStr string) map[string]string {
	cmd := exec.Command("httpx", "-u", urlStr, "--tech-detect", "--json", "--silent")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var data struct{ Tech []string `json:"tech"` }
	if json.Unmarshal(out, &data) != nil {
		return nil
	}
	tech := map[string]string{}
	re := regexp.MustCompile(`^([^:]+):\s*(.+)$`)
	for _, t := range data.Tech {
		m := re.FindStringSubmatch(t)
		if len(m) < 3 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(m[1]))
		ver := strings.TrimSpace(m[2])
		if ver == "unknown" || ver == "" {
			ver = ""
		}
		tech[name] = ver
	}
	return tech
}

func scanURL(urlStr string) Result {
	tech := runHttpx(urlStr)
	res := Result{URL: urlStr, Tech: tech}
	for t, v := range tech {
		cves := getCVEs(t, v)
		for i := range cves {
			cves[i].Exploits = getExploits(cves[i].ID)
			res.Vulns = append(res.Vulns, cves[i])
		}
	}
	return res
}

func printResults(results []Result) {
	mag := color.New(color.FgMagenta)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite)
	for _, r := range results {
		mag.Println(strings.Repeat("=", 60))
		cyan.Print("Target: ")
		color.New(color.Bold).Println(r.URL)
		mag.Println(strings.Repeat("=", 60))
		if len(r.Tech) == 0 {
			color.Yellow(" No technology detected.")
			continue
		}
		for name, ver := range r.Tech {
			color.Green("Detected: ")
			white.Print(strings.Title(name))
			if ver != "" {
				color.New(color.FgHiWhite).Print(" v" + ver)
			}
			fmt.Println()
			found := false
			for _, v := range r.Vulns {
				if !strings.Contains(strings.ToLower(v.Desc), name) && (ver == "" || !strings.Contains(v.Desc, ver)) {
					continue
				}
				found = true
				col := severityColors[v.Severity]
				if col == nil {
					col = severityColors["unknown"]
				}
				col.Printf("CVE: %s [%s] %s\n", v.ID, strings.ToUpper(v.Severity), v.Score)
				desc := regexp.MustCompile(`\s+`).ReplaceAllString(v.Desc, " ")
				if len(desc) > 180 {
					desc = desc[:180] + "..."
				}
				color.New(color.FgHiBlack).Println(" " + desc)
				if len(v.Exploits) > 0 {
					for _, e := range v.Exploits {
						color.Red("Exploit: " + e.Title + " ")
						color.Blue(e.URL)
						fmt.Println()
					}
				} else {
					color.New(color.FgHiBlack).Println(" No public exploit.")
				}
			}
			if !found {
				color.New(color.FgHiBlack).Println(" No relevant CVE.")
			}
		}
	}
}

func main() {
        printBanner()
	var urlFlag, fileFlag string
	var conc int
	flag.StringVar(&urlFlag, "u", "", "URL")
	flag.StringVar(&fileFlag, "f", "", "File")
	flag.IntVar(&conc, "c", 10, "Concurrency")
	flag.Parse()

	if _, err := exec.LookPath("httpx"); err != nil {
		fmt.Println("httpx not found.")
		os.Exit(1)
	}

	urls := []string{}
	if urlFlag != "" {
		urls = []string{urlFlag}
	} else if fileFlag != "" {
		f, _ := os.Open(fileFlag)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") {
				urls = append(urls, l)
			}
		}
		f.Close()
	} else {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if l != "" && !strings.HasPrefix(l, "#") {
				urls = append(urls, l)
			}
		}
	}
	if len(urls) == 0 {
		fmt.Println("No input.")
		os.Exit(1)
	}
	for i := range urls {
		if !strings.HasPrefix(urls[i], "http") {
			urls[i] = "http://" + urls[i]
		}
	}

	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	results := make([]Result, len(urls))
	mu := sync.Mutex{}

	for idx, u := range urls {
		wg.Add(1)
		go func(idx int, urlStr string) {
			defer wg.Done()
			sem <- struct{}{}
			res := scanURL(urlStr)
			mu.Lock()
			results[idx] = res
			mu.Unlock()
			<-sem
		}(idx, u)
	}
	wg.Wait()
	printResults(results)
}
