package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	security "github.com/dokosoko/complicatedauth-backend/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type emailMessage struct {
	DeliveryUID uuid.UUID
	To          string
	Subject     string
	Text        string
}

type emailSender interface {
	Send(context.Context, emailMessage) error
}

type unavailableEmailSender struct{}

func (unavailableEmailSender) Send(context.Context, emailMessage) error {
	return errors.New("email delivery is not configured")
}

type smtpEmailSender struct {
	address, from, username, password string
	startTLS                          bool
	timeout                           time.Duration
}

func configuredEmailSender(cfg Config) emailSender {
	if cfg.EmailSMTPAddress == "" || cfg.EmailFrom == "" {
		return unavailableEmailSender{}
	}
	return &smtpEmailSender{
		address: cfg.EmailSMTPAddress, from: cfg.EmailFrom,
		username: cfg.EmailSMTPUsername, password: cfg.EmailSMTPPassword,
		startTLS: cfg.EmailSMTPStartTLS, timeout: cfg.EmailDeliveryTimeout,
	}
}

func (s *smtpEmailSender) Send(ctx context.Context, message emailMessage) error {
	from, err := mail.ParseAddress(s.from)
	if err != nil {
		return fmt.Errorf("parse email sender: %w", err)
	}
	to, err := mail.ParseAddress(message.To)
	if err != nil {
		return fmt.Errorf("parse email recipient: %w", err)
	}
	host, _, err := net.SplitHostPort(s.address)
	if err != nil {
		return fmt.Errorf("parse SMTP address: %w", err)
	}
	timeout := s.timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return fmt.Errorf("connect SMTP server: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	client, err := smtp.NewClient(connection, host)
	if err != nil {
		return fmt.Errorf("initialize SMTP client: %w", err)
	}
	defer client.Close()
	if s.startTLS {
		if err = client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("start SMTP TLS: %w", err)
		}
	}
	if s.username != "" {
		if !s.startTLS {
			return errors.New("SMTP authentication requires STARTTLS")
		}
		if err = client.Auth(smtp.PlainAuth("", s.username, s.password, host)); err != nil {
			return fmt.Errorf("authenticate SMTP client: %w", err)
		}
	}
	if err = client.Mail(from.Address); err != nil {
		return fmt.Errorf("set SMTP sender: %w", err)
	}
	if err = client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("set SMTP recipient: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start SMTP message: %w", err)
	}
	messageIDDomain := host
	if at := strings.LastIndex(from.Address, "@"); at >= 0 {
		messageIDDomain = from.Address[at+1:]
	}
	buffer := bufio.NewWriter(writer)
	_, err = fmt.Fprintf(buffer,
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMessage-ID: <%s@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s\r\n",
		from.String(), to.String(), message.Subject, message.DeliveryUID, messageIDDomain, message.Text,
	)
	if err == nil {
		err = buffer.Flush()
	}
	closeErr := writer.Close()
	if err != nil {
		return fmt.Errorf("write SMTP message: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("finish SMTP message: %w", closeErr)
	}
	if err = client.Quit(); err != nil {
		return fmt.Errorf("quit SMTP client: %w", err)
	}
	return nil
}

type emailDeliveryPayload struct {
	DisplayName string `json:"display_name"`
	TenantName  string `json:"tenant_name"`
	Link        string `json:"link"`
}

func emailDeliveryContext(deliveryUID, field string) []byte {
	return []byte("email-delivery|" + deliveryUID + "|" + field)
}

func (s *Server) scheduleEmailDelivery(ctx context.Context, tx pgx.Tx, tenantUID, template, recipient string, payload emailDeliveryPayload) error {
	deliveryUID := uuid.New()
	recipientEncrypted, err := s.cfg.DataEncryptionKeys.Seal([]byte(recipient), emailDeliveryContext(deliveryUID.String(), "recipient"))
	if err != nil {
		return err
	}
	rawPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	payloadEncrypted, err := s.cfg.DataEncryptionKeys.Seal(rawPayload, emailDeliveryContext(deliveryUID.String(), "payload"))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO email_deliveries(
			uid,tenant_uid,template,
			recipient_key_version,recipient_nonce,recipient_ciphertext,
			payload_key_version,payload_nonce,payload_ciphertext
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
	`, deliveryUID, tenantUID, template,
		recipientEncrypted.KeyVersion, recipientEncrypted.Nonce, recipientEncrypted.Ciphertext,
		payloadEncrypted.KeyVersion, payloadEncrypted.Nonce, payloadEncrypted.Ciphertext)
	if err == nil {
		_, err = tx.Exec(ctx, `
			INSERT INTO background_jobs(uid,queue,job_type,deduplication_key,payload)
			VALUES($1,'email','email.delivery',$2,$3)
		`, uuid.New(), "email-delivery:"+deliveryUID.String(), map[string]any{"delivery_uid": deliveryUID})
	}
	return err
}

func (s *Server) deliverEmail(ctx context.Context, deliveryUID string) error {
	var (
		template, status                                          string
		recipientVersion, payloadVersion                          string
		recipientNonce, recipientCiphertext, payloadNonce, cipher []byte
	)
	err := s.db.QueryRow(ctx, `
		SELECT template,status,
		       recipient_key_version,recipient_nonce,recipient_ciphertext,
		       payload_key_version,payload_nonce,payload_ciphertext
		FROM email_deliveries WHERE uid=$1
	`, deliveryUID).Scan(&template, &status,
		&recipientVersion, &recipientNonce, &recipientCiphertext,
		&payloadVersion, &payloadNonce, &cipher)
	if errors.Is(err, pgx.ErrNoRows) || status == "delivered" {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load email delivery: %w", err)
	}
	recipient, err := s.cfg.DataEncryptionKeys.Open(security.EncryptedValue{KeyVersion: recipientVersion, Nonce: recipientNonce, Ciphertext: recipientCiphertext}, emailDeliveryContext(deliveryUID, "recipient"))
	if err != nil {
		return fmt.Errorf("decrypt email recipient: %w", err)
	}
	rawPayload, err := s.cfg.DataEncryptionKeys.Open(security.EncryptedValue{KeyVersion: payloadVersion, Nonce: payloadNonce, Ciphertext: cipher}, emailDeliveryContext(deliveryUID, "payload"))
	if err != nil {
		return fmt.Errorf("decrypt email payload: %w", err)
	}
	var payload emailDeliveryPayload
	if err = json.Unmarshal(rawPayload, &payload); err != nil {
		return fmt.Errorf("decode email payload: %w", err)
	}
	subject, body, err := renderEmail(template, payload)
	if err != nil {
		return err
	}
	parsedUID, _ := uuid.Parse(deliveryUID)
	if err = s.email.Send(ctx, emailMessage{DeliveryUID: parsedUID, To: string(recipient), Subject: subject, Text: body}); err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `UPDATE email_deliveries SET status='delivered',delivered_at=clock_timestamp() WHERE uid=$1 AND status='pending'`, deliveryUID)
	return err
}

func renderEmail(template string, payload emailDeliveryPayload) (string, string, error) {
	salutation := "Hello"
	if payload.DisplayName != "" {
		salutation += " " + payload.DisplayName
	}
	switch template {
	case "tenant_email_verification":
		return "Verify your ComplicatedAuth email", fmt.Sprintf("%s,\n\nVerify your email for %s:\n\n%s\n\nThis link expires in 24 hours. If you did not request it, you can ignore this message.", salutation, payload.TenantName, payload.Link), nil
	case "tenant_password_reset":
		return "Reset your ComplicatedAuth password", fmt.Sprintf("%s,\n\nReset your password for %s:\n\n%s\n\nThis link expires in 30 minutes and can be used once. If you did not request it, you can ignore this message.", salutation, payload.TenantName, payload.Link), nil
	case "tenant_invitation":
		return "You were invited to ComplicatedAuth", fmt.Sprintf("%s,\n\nYou were invited to join %s:\n\n%s\n\nThis link expires in 7 days and can be used once.", salutation, payload.TenantName, payload.Link), nil
	default:
		return "", "", fmt.Errorf("unsupported email template %q", template)
	}
}
