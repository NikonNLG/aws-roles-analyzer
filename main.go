package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Result contains results of querying on all events
type Result struct {
	// Count     int
	EventName map[string]int
}

type Record struct {
	AwsRegion   string `json:"awsRegion"`
	ErrorCode   string `json:"errorCode"`
	EventID     string `json:"eventID"`
	EventName   string `json:"eventName"`
	EventSource string `json:"eventSource"`
	Resources   []struct {
		ARN       string `json:"ARN"`
		AccountID string `json:"accountId"`
		Type      string `json:"type"`
	} `json:"resources"`
	UserIdentity struct {
		Type           string `json:"type"`
		UserName       string `json:"userName"`
		Arn            string `json:"arn"`
		SessionContext struct {
			SessionIssuer struct {
				Type string `json:"type"`
				Arn  string `json:"arn"`
			}
		}
	} `json:"userIdentity"`
}

type Events struct {
	Records []Record
}

func listFiles(dir string) []string {
	cleanedList := make([]string, 0)
	x, err := ioutil.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	// Remove all files that ends not to json
	for f := range x {
		if x[f].IsDir() {
			nestedDir := fmt.Sprintf("%v/%v", dir, x[f].Name())
			cleanedList = append(cleanedList, listFiles(nestedDir)...)
		} else if strings.HasSuffix(x[f].Name(), ".json") || strings.HasSuffix(x[f].Name(), ".json.gz") {
			// TODO: Use regex
			cleanedList = append(cleanedList, fmt.Sprintf("%v/%v", dir, x[f].Name()))
		} else {
			println("skipping " + x[f].Name())
		}
	}
	return cleanedList
}

func parseFile(roleName string, eventType string, file string) []Record {
	f, err := os.Open(filepath.Clean(file))
	var fileContent []byte
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if strings.HasSuffix(f.Name(), ".gz") {
		// Need to unpack it first
		reader, err := gzip.NewReader(f)
		if err != nil {
			panic(err)
		}
		defer reader.Close()

		fileContent, err = ioutil.ReadAll(reader)
		if err != nil {
			panic(err)
		}
	} else {
		fileContent, err = ioutil.ReadAll(f)
		if err != nil {
			panic(err)
		}
	}

	// TODO: Remove Events struct
	var tmp Events
	err = json.Unmarshal(fileContent, &tmp)
	if err != nil {
		panic(err)
	}

	var allRecords []Record
	var cleanRecords []Record
	allRecords = append(allRecords, tmp.Records...)

	for i := 0; i < len(allRecords); i++ {
		if eventType == "role" {
			current := allRecords[i].UserIdentity.SessionContext.SessionIssuer

			if current.Type == "Role" && strings.HasSuffix(current.Arn, roleName) {
				cleanRecords = append(cleanRecords, allRecords[i])
			}
			currentSts := allRecords[i].Resources
			if len(currentSts) != 0 {
				if currentSts[0].Type == "AWS::IAM::Role" && strings.HasSuffix(currentSts[0].ARN, roleName) {
					cleanRecords = append(cleanRecords, allRecords[i])
				}
			}
		}

		if eventType == "user" {
			current := allRecords[i]
			if current.UserIdentity.Type == "IAMUser" && strings.HasSuffix(current.UserIdentity.Arn, roleName) {
				cleanRecords = append(cleanRecords, allRecords[i])
			}
		}

	}
	return cleanRecords
}

func main() {
	var records []Record
	allRequests := make(map[string]Result)

	roleName := flag.String("roleName", "", "Role name for analyze")
	userName := flag.String("userName", "", "User name for analyze")
	dirName := flag.String("dirName", "", "Path for CloudTrail logs")
	concurrency := flag.Int("concurrency", 20, "Number of concurrent threads")
	flag.Parse()

	if *roleName == "" && *userName == "" {
		println("You must provide at least role or user name")
		os.Exit(1)
	}

	if *dirName == "" {
		println("You need provide path to logs")
		os.Exit(1)
	}

	files := listFiles(*dirName)

	sem := make(chan bool, *concurrency)
	// TODO: counter for events is wrong for 10-20 events. Need to fix it
	for _, v := range files {
		sem <- true
		go func() {
			defer func() { <-sem }()
			if *roleName != "" {
				records = append(records, parseFile(*roleName, "role", v)...)
			}
			if *userName != "" {
				records = append(records, parseFile(*userName, "user", v)...)
			}
		}()
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	// println("Results:" + len(records))
	for i := 0; i < len(records); i++ {
		evSource := records[i].EventSource
		evName := records[i].EventName
		v, ok := allRequests[evSource]
		if !ok {
			v = Result{}
			v.EventName = make(map[string]int)
		}
		v.EventName[evName]++
		allRequests[evSource] = v
	}
	println("Result of scanning:")
	for source, event := range allRequests {
		for k, v := range event.EventName {
			fmt.Printf("%v:%v - %v\n", source, k, v)
		}
	}
}
