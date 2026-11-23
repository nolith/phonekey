package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"

	"phonekey/internal/store"
)

// pusher sends Web Push notifications to every registered subscription.
type pusher struct {
	store   *store.Store
	log     *slog.Logger
	subject string
	public  string
	private string
	client  *http.Client
}

// PushMessage is the JSON the service worker receives.
type PushMessage struct {
	ID    string `json:"id,omitempty"`
	Title string `json:"title"`
	Body  string `json:"body"`
}

func loadVAPID(ctx context.Context, st *store.Store) (public, private string, err error) {
	public, err1 := st.Setting(ctx, "vapid_public")
	private, err2 := st.Setting(ctx, "vapid_private")
	if err1 == nil && err2 == nil {
		return public, private, nil
	}
	if !errors.Is(err1, store.ErrNotFound) && err1 != nil {
		return "", "", err1
	}
	private, public, err = webpush.GenerateVAPIDKeys()
	if err != nil {
		return "", "", err
	}
	if err := st.SetSetting(ctx, "vapid_public", public); err != nil {
		return "", "", err
	}
	return public, private, st.SetSetting(ctx, "vapid_private", private)
}

func (p *pusher) send(ctx context.Context, msg PushMessage) {
	subs, err := p.store.PushSubscriptions(ctx)
	if err != nil {
		p.log.Error("push: list subscriptions", "err", err)
		return
	}
	payload, _ := json.Marshal(msg)
	for _, sub := range subs {
		var s webpush.Subscription
		if err := json.Unmarshal([]byte(sub.Subscription), &s); err != nil {
			p.log.Warn("push: bad stored subscription", "id", sub.ID, "err", err)
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := webpush.SendNotificationWithContext(sctx, payload, &s, &webpush.Options{
			HTTPClient:      p.client,
			// webpush-go adds "mailto:" to anything that isn't an https: URL.
			Subscriber:      strings.TrimPrefix(p.subject, "mailto:"),
			VAPIDPublicKey:  p.public,
			VAPIDPrivateKey: p.private,
			TTL:             120,
			Urgency:         webpush.UrgencyHigh,
		})
		cancel()
		if err != nil {
			p.log.Warn("push: send failed", "endpoint", sub.Endpoint, "err", err)
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
			p.log.Info("push: subscription gone, removing", "endpoint", sub.Endpoint)
			p.store.DeletePushSubscription(ctx, sub.ID)
		case resp.StatusCode >= 300:
			p.log.Warn("push: rejected", "endpoint", sub.Endpoint, "status", resp.StatusCode, "body", string(body))
		default:
			p.log.Debug("push: sent", "endpoint", sub.Endpoint, "status", resp.StatusCode)
		}
	}
}
