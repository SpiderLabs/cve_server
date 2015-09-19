package main

import (
  "fmt"
  "github.com/bndr/gopencils"
  "errors"
)

type Cvss struct {
  Score string
  AccessVector string
  AccessComplexity string
  Authentication string
  ConfidentialityImpact string
  IntegrityImpact string
  AvailabilityImpact string
  Source string
  GeneratedOnDatetime string
  Vector string
}

type Reference struct {
  Type string
  Name string
  Href string
  Content string
}

type Cve struct {
  Id string
  Summary string
  Cwe string
  PublishedAt string
  UpdatedAt string
  Cvss Cvss
  References []Reference
  Cpes []string
}

type CveClient struct {
  api *gopencils.Resource
}

func Start(url string) (*CveClient, error) {
  if url != "" {
    api := gopencils.Api(url)
    cve_client := CveClient{api: api}
    return &cve_client, nil
  } else {
    return nil, errors.New("You must specify an url")
  }
}

func (c *CveClient) DetailsPerCve(cveId string) (*Cve, error) {
   resource := c.api.Res("cve")
   cve := new(Cve)
    _, err := resource.Id(cveId, cve).Get()

   if err != nil {
     return nil, err
   } else {
     return cve, nil
   }
}

func (c *CveClient) CvesPerCpe(cpe string) (*[]string, error) {
   resource := c.api.Res("cpe")
   cves := new([]string)
   _, err := resource.Id(cpe, cves).Get()

   if err != nil {
     return nil, err
   } else {
     return cves, nil
   }
}

func (c *CveClient) Cpes() (*[]string, error) {
   cpes := new([]string)
   resource := c.api.Res("cpe", cpes)
   _, err := resource.Get()

   if err != nil {
     return nil, err
   } else {
     return cpes, nil
   }
}

func main() {
  client, err := Start("http://0.0.0.0:9292/v1")

  if err != nil {
    fmt.Println(err)
  } else {

    cve, cve_err := client.DetailsPerCve("CVE-2015-0001")
    if cve_err != nil {
      fmt.Println(cve_err)
    } else {
      fmt.Println(cve.Id)
      fmt.Println(cve.Summary)
      fmt.Println(cve.Cvss.Score)
    }

    // cves, _ := client.CvesPerCpe("oracle:application_server_10g")
    // for _, cve := range *cves {
    //   fmt.Println(cve)
    // }

    // cpes, _ := client.Cpes()
    // for _, cpe := range *cpes {
    //   fmt.Println(cpe)
    // }
  }
}
