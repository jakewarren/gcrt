package app

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

var cmd = &cobra.Command{
	Use:   "crt",
	Short: "crt is a tool to query the Certificate Transparency Logs",
	Long: `crt is a tool to query the Certificate Transparency Logs
				  it does so by querying https://crt.sh
				  Complete documentation is available at https://github.com/jhinds/crt`,
	Run: func(cmd *cobra.Command, args []string) {
		GetCerts()
	},
}

func Execute() {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

const crtUrl = "https://crt.sh"

var domain string

var between string

var days string

func init() {
	cmd.PersistentFlags().StringVar(&domain, "domain", "", "Domain to find certificates for. % is a wildcard")
	cmd.PersistentFlags().StringVar(&days, "days", "", "How many days back to query")
	cmd.PersistentFlags().StringVar(&between, "between", "", "The dates to run the query for in the format start-date:end-date.  The dates should have the format YYYY-MM-DD")
}

func GetCerts() {
	cleanDomain := strings.Replace(domain, "%", "%25", -1)
	url := fmt.Sprintf("%s/?q=%s&output=json", crtUrl, cleanDomain)
	client := &http.Client{
		Timeout: time.Second * 3,
	}
	resp, err := client.Get(url)
	if err != nil {
		errors.Wrap(err, "Error Getting Response")
	}
	defer resp.Body.Close()
	if err != nil {
		errors.Wrap(err, "Error Getting Response")
	}
	contents, err := ioutil.ReadAll(resp.Body)
	fmt.Printf("%s\n", string(contents))

}
