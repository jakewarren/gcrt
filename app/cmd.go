package app

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/cli"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "gcrt",
	Short: "gcrt is a tool to query the Certificate Transparency Logs",
	Long: `gcrt is a tool to query the Certificate Transparency Logs
				  it does so by querying https://crt.sh
				  Complete documentation is available at https://github.com/jhinds/gcrt`,
	Run: func(cmd *cobra.Command, args []string) {
		GetCerts()
	},
}

// Execute runs the application
func Execute() {
	log.SetHandler(cli.New(os.Stderr))
	if err := cmd.Execute(); err != nil {
		log.Fatal(err.Error())
	}
}

const gcrtURL = "https://crt.sh"

var domain string
var between string
var days int
var count bool

func init() {
	cmd.PersistentFlags().StringVar(&between, "between", "", "The dates to run the query for in the format start-date:end-date.  The dates should have the format YYYY-MM-DD")
	cmd.PersistentFlags().BoolVarP(&count, "count", "c", false, "Don't return the results just the count")
	cmd.PersistentFlags().IntVar(&days, "days", -1, "How many days back to query")
	cmd.PersistentFlags().StringVarP(&domain, "domain", "d", "", "Domain to find certificates for. % is a wildcard")
	cmd.MarkPersistentFlagRequired("domain")
}

// GetCerts will query the Certificate logs and return the result
func GetCerts() {
	cleanDomain := strings.Replace(domain, "%", "%25", -1)
	url := fmt.Sprintf("%s/?q=%s&output=json", gcrtURL, cleanDomain)
	client := &http.Client{
		Timeout: time.Second * 3,
	}
	resp, err := client.Get(url)
	if err != nil {
		log.WithError(err).Fatal("Error Getting Response")
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Fatal("Error Reading Body")
	}

	// massage the crt.sh output since it isn't valid JSON
	contents = []byte(`[` + strings.Replace(string(contents), "}{", "},{", -1) + `]`)

	var certs []CertResponse
	err = json.Unmarshal(contents, &certs)
	if err != nil {
		log.WithError(err).Fatal("Error Unmarshalling JSON")
	}

	// remove duplicate certs since crt.sh returns both the leaf certificate and precertificate
	certs = removeDuplicateCerts(certs)

	// outputCerts will hold remaining certs after date filtering (if requested)
	var outputCerts []CertResponse

	if len(between) > 0 { // filter by date range
		bDates := reSubMatchMap(`(?P<startdate>\d{4}-\d{2}-\d{2}):(?P<enddate>\d{4}-\d{2}-\d{2})`, between)

		var startDate, endDate time.Time

		if d, ok := bDates["startdate"]; ok {
			startDate, err = time.Parse("2006-01-02", d)
			if err != nil {
				log.WithError(err).Fatal("Error parsing start date")
			}
		} else {
			log.Fatal("start date not provided in valid format")
		}
		if d, ok := bDates["enddate"]; ok {
			endDate, err = time.Parse("2006-01-02", d)
			if err != nil {
				log.WithError(err).Fatal("Error parsing end date")
			}
			endDate = endDate.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		} else {
			log.Fatal("end date not provided in valid format")
		}

		for _, c := range certs {
			certDate, certParseErr := time.Parse("2006-01-02T15:04:05", c.NotBefore)

			if certParseErr != nil {
				log.WithError(certParseErr).Errorf("error parsing date in cert %d", c.MinCertID)
				continue
			}

			if certDate.After(startDate) && certDate.Before(endDate) {
				outputCerts = append(outputCerts, c)
			}
		}
	} else if days > 0 { // filter certs by days ago threshold
		now := time.Now()
		thresholdDate := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -days)

		for _, c := range certs {
			certDate, certParseErr := time.Parse("2006-01-02T15:04:05", c.NotBefore)
			if certParseErr != nil {
				log.WithError(certParseErr).Errorf("error parsing date in cert %d", c.MinCertID)
				continue
			}
			if certDate.After(thresholdDate) {
				outputCerts = append(outputCerts, c)
			}
		}
	} else {
		outputCerts = certs
	}

	if count {
		fmt.Printf("Number of certs found: %d\n", len(outputCerts))
		return
	}
	if len(outputCerts) > 1 {
		output, _ := json.MarshalIndent(&outputCerts, "", "    ")
		fmt.Println(string(output))
	}
}

type enrichedCertResponse CertResponse

// MarshalJSON adds in a link to the crt.sh page for each cert
func (c CertResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		CertShLink string `json:"crt_sh_link"`
		enrichedCertResponse
	}{
		CertShLink:           `https://crt.sh/?id=` + strconv.Itoa(c.MinCertID),
		enrichedCertResponse: enrichedCertResponse(c),
	})
}

func removeDuplicateCerts(certs []CertResponse) []CertResponse {

	m := make(map[string]struct{})
	dedupedCerts := make([]CertResponse, 0)

	for _, c := range certs {
		// keep the first cert which is the leaf certificate
		if _, ok := m[c.NameValue+c.NotBefore]; !ok {
			m[c.NameValue+c.NotBefore] = struct{}{}
			dedupedCerts = append(dedupedCerts, c)
		}
	}
	return dedupedCerts
}

func reSubMatchMap(regEx, text string) (groupMatchMap map[string]string) {
	var compRegEx = regexp.MustCompile(regEx)
	match := compRegEx.FindStringSubmatch(text)
	groupMatchMap = make(map[string]string)
	for i, name := range compRegEx.SubexpNames() {
		if i > 0 && i <= len(match) {
			groupMatchMap[name] = match[i]
		}
	}
	return
}
