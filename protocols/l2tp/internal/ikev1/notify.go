package ikev1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Notification payloads (RFC 2408 section 3.14).
//
// IKEv1 has no separate error channel: a peer reports both failures and status
// events by sending a Notification payload, and in phase 1 it commonly arrives
// inside the very exchange type Main Mode uses. Without recognizing them, a
// notify reads as a malformed Main Mode message and the session fails with a
// misleading parse error instead of the reason the peer actually gave.
//
// Types below 16384 are errors and end the exchange; the rest are status and are
// informational only (DPD keepalives and INITIAL_CONTACT arrive this way).

const notifyStatusBase = 16384

// notifyNames is the error range from RFC 2408 section 3.14.1. Keeping the
// numeric mapping complete matters here: several adjacent values describe
// different failure classes (for example invalid hash versus authentication).
var notifyNames = map[uint16]string{
	1:  "INVALID-PAYLOAD-TYPE",
	2:  "DOI-NOT-SUPPORTED",
	3:  "SITUATION-NOT-SUPPORTED",
	4:  "INVALID-COOKIE",
	5:  "INVALID-MAJOR-VERSION",
	6:  "INVALID-MINOR-VERSION",
	7:  "INVALID-EXCHANGE-TYPE",
	8:  "INVALID-FLAGS",
	9:  "INVALID-MESSAGE-ID",
	10: "INVALID-PROTOCOL-ID",
	11: "INVALID-SPI",
	12: "INVALID-TRANSFORM-ID",
	13: "ATTRIBUTES-NOT-SUPPORTED",
	14: "NO-PROPOSAL-CHOSEN",
	15: "BAD-PROPOSAL-SYNTAX",
	16: "PAYLOAD-MALFORMED",
	17: "INVALID-KEY-INFORMATION",
	18: "INVALID-ID-INFORMATION",
	19: "INVALID-CERT-ENCODING",
	20: "INVALID-CERTIFICATE",
	21: "CERT-TYPE-UNSUPPORTED",
	22: "INVALID-CERT-AUTHORITY",
	23: "INVALID-HASH-INFORMATION",
	24: "AUTHENTICATION-FAILED",
	25: "INVALID-SIGNATURE",
	26: "ADDRESS-NOTIFICATION",
	27: "NOTIFY-SA-LIFETIME",
	28: "CERTIFICATE-UNAVAILABLE",
	29: "UNSUPPORTED-EXCHANGE-TYPE",
	30: "UNEQUAL-PAYLOAD-LENGTHS",
}

// notifyType extracts the message type from a Notification payload body.
func notifyType(body []byte) (uint16, bool) {
	// DOI (4) | Protocol-ID (1) | SPI Size (1) | Notify Message Type (2).
	if len(body) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint16(body[6:8]), true
}

// handleNotifies inspects a message's Notification payloads. It reports an error
// for a peer-signalled failure, and otherwise reports whether the message was
// purely informational and should be ignored rather than fed to the Main Mode or
// Quick Mode handlers.
func (s *Session) handleNotifies(payloads []payload) (informational bool, err error) {
	var sawNotify bool
	for _, p := range payloads {
		if p.typ != payloadNotify {
			continue
		}
		sawNotify = true
		typ, ok := notifyType(p.body)
		if !ok {
			continue
		}
		if typ < notifyStatusBase {
			name := notifyNames[typ]
			if name == "" {
				name = fmt.Sprintf("error %d", typ)
			}
			return false, fmt.Errorf("ikev1: peer reported %s", name)
		}
		s.logger.Printf("ikev1: status notification %d from peer", typ)
	}
	// A message carrying nothing but notifications is not a step in the
	// exchange, so the state machine must not advance on it.
	if !sawNotify {
		return false, nil
	}
	for _, p := range payloads {
		switch p.typ {
		case payloadNotify, payloadVendorID:
		default:
			return false, nil
		}
	}
	return true, nil
}

// handleInformational processes an Informational exchange interleaved with an
// in-progress phase 1 or phase 2 exchange. Peers use these messages for the
// actual rejection reason and for deleting an SA; dropping them leaves the
// caller with only a later, misleading retransmission timeout.
func (s *Session) handleInformational(h header, first uint8, rest []byte) error {
	s.logger.Printf("ikev1: received Informational exchange: encrypted=%v message-id=%08x",
		h.flags&flagEncryption != 0, h.messageID)

	var payloads []payload
	if h.flags&flagEncryption == 0 {
		var err error
		payloads, _, err = parsePayloads(first, rest)
		if err != nil {
			return fmt.Errorf("ikev1: parse plaintext Informational exchange: %w", err)
		}
	} else {
		if s.keys == nil {
			return errors.New("ikev1: encrypted Informational exchange before key derivation")
		}
		iv := s.keys.quickModeIV(h.messageID)
		var plain []byte
		var consumed int
		var err error
		payloads, plain, consumed, err = s.recvDecrypt(&iv, first, rest)
		if err != nil {
			return fmt.Errorf("ikev1: decrypt Informational exchange: %w", err)
		}
		if len(payloads) == 0 || payloads[0].typ != payloadHash {
			return errors.New("ikev1: encrypted Informational exchange without leading HASH")
		}
		want := s.keys.prf.Apply(s.keys.skeyidA,
			concat(be32(h.messageID), afterHash(plain, payloads, consumed)))
		if !constEq(want, payloads[0].body) {
			return errors.New("ikev1: Informational HASH verification failed")
		}
	}

	if _, err := s.handleNotifies(payloads); err != nil {
		return err
	}
	for _, p := range payloads {
		if p.typ != payloadDelete {
			continue
		}
		protocol := "unknown"
		if len(p.body) >= 5 {
			switch p.body[4] {
			case protoISAKMP:
				protocol = "IKE"
			case protoESP:
				protocol = "ESP"
			default:
				protocol = fmt.Sprintf("protocol %d", p.body[4])
			}
		}
		return fmt.Errorf("ikev1: peer deleted the %s SA while awaiting exchange %d", protocol, s.expectedExchange())
	}
	return nil
}
