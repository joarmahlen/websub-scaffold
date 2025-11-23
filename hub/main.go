package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type Subscription struct {
	Callback string
	Secret  string
}

type Message struct {
    Content  string
	Topic string 
}

var (
    subscriptions = make(map[string][]Subscription)
    subsMutex     sync.RWMutex
)

var clientWithTimeout = &http.Client{
	Timeout: 10 * time.Second,
}

func generateChallenge(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}


func handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	mode := r.Form.Get("hub.mode")
	topic := r.Form.Get("hub.topic")
	callback := r.Form.Get("hub.callback")
	secret := r.Form.Get("hub.secret")

	if len(secret) > 200 || len(secret) == 0 {
		http.Error(w, "Secret too long or doesn't exist", http.StatusBadRequest)
		return
	}

	if callback == "" || topic == "" || mode == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	callbackURL, err := url.Parse(callback)
	if err != nil {
		http.Error(w, "Invalid callback URL", http.StatusBadRequest)
		return
	}

	challenge, err := generateChallenge(32)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	q := callbackURL.Query()
	q.Set("hub.mode", mode)
	q.Set("hub.topic", topic)
	q.Set("hub.challenge", challenge)
	callbackURL.RawQuery = q.Encode()

	verifyURL := callbackURL.String()
	
	resp, err := clientWithTimeout.Get(verifyURL)
	if err != nil {
		http.Error(w, "Intent verification failed", http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	if body != challenge {
		http.Error(w, "Intent verification failed (challenge mismatch)", http.StatusBadRequest)
		return
	}

	subsMutex.Lock()

	for _, sub := range subscriptions[topic] {
		if sub.Callback == callback {
			http.Error(w, "Subscription for this topic already exists", http.StatusBadRequest)
			subsMutex.Unlock()
			return
		}
	}

	subscriptions[topic] = append(subscriptions[topic], Subscription{
		Callback: callback,
		Secret:   secret,
	})
	subsMutex.Unlock()

	w.WriteHeader(http.StatusAccepted)
	fmt.Fprintln(w, "Subscription accepted")
}

func handlePublish(w http.ResponseWriter, r *http.Request) {
	message := Message{
		Content: r.FormValue("message"),
		Topic: r.FormValue("topic"),
	}

	jsonBytes, err := json.Marshal(message)
	if err != nil {
		http.Error(w, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	subsMutex.RLock()
	matchingSubs := subscriptions[message.Topic]
	subsMutex.RUnlock()

	var wg sync.WaitGroup
	wg.Add(len(matchingSubs))

	for _, sub := range matchingSubs {
		go publishToSubscriber(sub, jsonBytes, &wg)
	}

	wg.Wait()

	fmt.Fprintln(w, "New message published!")	
}

func publishToSubscriber(sub Subscription, jsonBytes []byte, wg *sync.WaitGroup) {
	defer wg.Done()

	mac := hmac.New(sha256.New, []byte(sub.Secret))
	mac.Write(jsonBytes)
	signature := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest("POST", sub.Callback, bytes.NewBuffer(jsonBytes))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature", "sha256="+signature)

	resp, err := clientWithTimeout.Do(req)
	if err != nil {
		log.Printf("Failed to publish to subscriber: %v", err)
		return
	}
	defer resp.Body.Close()
}

func main() {
	http.HandleFunc("/", handleSubscribe)
	http.HandleFunc("/publish", handlePublish)
	log.Fatal(http.ListenAndServe(":9090", nil))
}
