# cvefinder

![Screenshot](screenshot.png)

Go tool to detect technologies via httpx, search CVEs on NVD, exploits on Exploit-DB.
## Usage

```bash
go build -o cvefinder cvefinder.go
./cvefinder -u https://example.com/
# or -f urls.txt -c 20
# or echo "https://example.com/" | cvefinder

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

