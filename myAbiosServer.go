package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/AbiosGaming/go-sdk-v2/structs"
	"golang.org/x/time/rate"
)

const (
	defaultRequestPerSecond = 5
	defaultRequestPerMinute = 300
	abiosBaseURL            = "https://api.abiosgaming.com/v2/"
)

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type client struct {
	userName string
	passWord string
	oauth    accessToken
}

var currentLiveSeries []structs.Series

// 1 request per second, burst rate of 5
var limiter = NewIPRateLimiter(defaultRequestPerSecond, 5)
var lastAuthentication int64 //timestamp for the last time authentication occured

func newClient(username string, password string) (*client, error) {
	//set up the client, issue out an auth token, return the handle to the client

	clientHandle := new(client)
	clientHandle.userName = username
	clientHandle.passWord = password

	err := clientHandle.authenticate()
	return clientHandle, err

}

// IPRateLimiter ... Implements a token bucket rate limiter algorithm.
type IPRateLimiter struct {
	ips             map[string]*rate.Limiter
	mu              *sync.RWMutex
	tokensPerSecond rate.Limit
	burstSize       int
}

// NewIPRateLimiter ... Constructor for IPRateLimiter
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips:             make(map[string]*rate.Limiter),
		mu:              &sync.RWMutex{},
		tokensPerSecond: r,
		burstSize:       b,
	}
	return i
}

// AddIP ... Creates an
func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.tokensPerSecond, i.burstSize)
	i.ips[ip] = limiter
	return limiter
}

// GetLimiter returns the rate limiter for the provided IP address if it exists.
// Otherwise calls AddIP to add IP address to the map
func (i *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	i.mu.Lock()
	limiter, exists := i.ips[ip]

	if !exists {
		i.mu.Unlock()
		return i.AddIP(ip)
	}

	i.mu.Unlock()

	return limiter
}

func (c *client) authenticate() error {
	// handles authentication

	url := abiosBaseURL + "oauth/access_token"
	payload := strings.NewReader("grant_type=client_credentials&client_id=" + c.userName + "&client_secret=" + c.passWord)
	req, err := http.NewRequest("POST", url, payload)
	req.Header.Add("content-type", "application/x-www-form-urlencoded")

	if err != nil {
		return err
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	//check the response code
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("error: " + string(res.StatusCode) + string(body))
	}

	dec := json.NewDecoder(bytes.NewBuffer(body))
	c.oauth = accessToken{}
	err = dec.Decode(&c.oauth)
	if err != nil {
		return err
	}

	lastAuthentication = time.Now().Unix()
	return nil
}

func (c *client) retrieveLiveSeriesData() {
	// Retrieve live series data from Abios API and cache the results in memory

	// TODO: Implement reauthentication procedures
	// if c.oauth.ExpiresIn < 3600 {
	// 	log.Println("expire in " + string(c.oauth.ExpiresIn))
	// }
	// expires := (time.Now().Unix() - lastAuthentication) /
	// log.Println("expire in " + strconv.FormatInt(expires, 10))

	// Returns a list of currently live series.
	url := "https://api.abiosgaming.com/v2/series"
	// How can I turn paramters into QueryString?
	params := "?is_over=False&starts_before=now&sort&is_postponed=false"
	// TODO: can I make the hardcoded url less ugly?
	token := "&access_token=" + c.oauth.AccessToken

	url += params + token

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Println("An error has occured when creating the GET request, time: " + time.Now().String())
		log.Println(err)
		return
	}
	req.Header.Add("Authorization", "no-cache")
	httpClient := &http.Client{Timeout: 10 * time.Second}

	res, err := httpClient.Do(req)

	if err != nil {
		log.Println("An error has occured when performing the GET request, time: " + time.Now().String())
		log.Println(err)
		return
	}
	result, err := ioutil.ReadAll(res.Body)

	if err != nil {
		log.Println("An error has occured when reading the response, time: " + time.Now().String())
		log.Println(err)
		return
	}

	pages := structs.PaginatedSeries{}
	err = json.Unmarshal(result, &pages)

	if err != nil {
		log.Println("An error has occured during result unmarshalling, time: " + time.Now().String())
		log.Println(err)
		return
	}

	for _, series := range pages.Data {
		currentLiveSeries = append(currentLiveSeries, series)
	}

	log.Println("Latest data retrieved at: " + time.Now().String())

}

func (c *client) liveSeriesHandler(w http.ResponseWriter, r *http.Request) {
	//Returns a list of series currently live from cached results

	if len(currentLiveSeries) == 0 {
		fmt.Fprintf(w, "There are currently no live matches, please check back later")
		//TODO: In the resource retriever, get a list of expected match start time might be a good idea.
	} else {
		payload, err := json.MarshalIndent(currentLiveSeries, "", "\t")
		if err != nil {
			log.Println("Unable to marshal response")
			return // Since we couldn't marshal proper JSON we don't want to write anything
		}
		w.Write(payload)
	}
}

func (c *client) livePlayersHandler(w http.ResponseWriter, r *http.Request) {
	// Returns a list of currently live teams.

	currentLivePlayers := make([]structs.Player, 0)

	for _, series := range currentLiveSeries {
		for _, roster := range series.Rosters {
			for _, player := range roster.Players {
				currentLivePlayers = append(currentLivePlayers, player)
			}
		}
	}

	if len(currentLivePlayers) == 0 {
		fmt.Fprintf(w, "There are currently no live matches, please check back later")
		//TODO: In the resource retriever, get a list of expected match start time might be a good idea.
	} else {
		payload, err := json.MarshalIndent(currentLivePlayers, "", "\t")
		if err != nil {
			log.Println("Unable to marshal response")
			return // Since we couldn't marshal proper JSON we don't want to write anything
		}
		w.Write(payload)

	}
}

func (c *client) liveTeamsHandler(w http.ResponseWriter, r *http.Request) {
	// Returns a list of currently live teams.
	currentLiveTeams := make([]structs.Team, 0)

	for _, series := range currentLiveSeries {
		for _, roster := range series.Rosters {
			for _, team := range roster.Teams {
				currentLiveTeams = append(currentLiveTeams, team)
			}
		}
	}

	if len(currentLiveTeams) == 0 {
		fmt.Fprintf(w, "There are currently no live matches, please check back later")
		//TODO: In the resource retriever, get a list of expected match start time might be a good idea.
	} else {
		payload, err := json.MarshalIndent(currentLiveTeams, "", "\t")
		if err != nil {
			log.Println("Unable to marshal response")
			return // Since we couldn't marshal proper JSON we don't want to write anything
		}
		w.Write(payload)

	}
}

func pollAbiosAPI(frequencyInSeconds int32, c *client) {
	// Retrieves live series data from Abios API by poll frequency.
	for {
		<-time.After(time.Duration(frequencyInSeconds) * time.Second)
		c.retrieveLiveSeriesData()
	}
}

func limitMiddleware(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := limiter.GetLimiter(r.RemoteAddr)
		if !limiter.Allow() {
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// fmt.Println("hello")

	username := os.Getenv("USERNAME")
	password := os.Getenv("PASSWORD")

	fmt.Println("hello" + username + password)

	resourceFetcher, err := newClient(username, password)

	if err != nil {
		log.Println("An error has occured during authentication, please check your credentials in the Dockerfile")
		log.Println(err)
		os.Exit(1)
	}

	resourceFetcher.retrieveLiveSeriesData()

	// Update our buffer every 30 seconds
	go pollAbiosAPI(30, resourceFetcher)

	mux := http.NewServeMux()
	mux.HandleFunc("/series/live", resourceFetcher.liveSeriesHandler)
	mux.HandleFunc("/players/live", resourceFetcher.livePlayersHandler)
	mux.HandleFunc("/teams/live", resourceFetcher.liveTeamsHandler)

	log.Fatal(http.ListenAndServe(":8080", limitMiddleware(mux)))
}
