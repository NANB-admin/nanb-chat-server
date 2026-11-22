package turn

import "strings"

// nearEuropeCountries are the viewer countries whose nearest relay is the
// Frankfurt one: Europe, the Middle East, Africa, the Caucasus / Central Asia
// and the Indian subcontinent. Everyone else (the Americas, East Asia, Oceania)
// keeps the default California relay.
//
// Why it matters: a call is relay-only, so every packet goes phone -> relay ->
// phone. From Jordan the California relay is ~250 ms away (a 465 ms call round
// trip); Frankfurt is ~90 ms (~180 ms round trip).
var nearEuropeCountries = toSet(
	// Europe
	"AL", "AD", "AT", "BY", "BE", "BA", "BG", "HR", "CY", "CZ", "DK", "EE", "FI",
	"FR", "DE", "GR", "HU", "IS", "IE", "IT", "XK", "LV", "LI", "LT", "LU", "MT",
	"MD", "MC", "ME", "NL", "MK", "NO", "PL", "PT", "RO", "RU", "SM", "RS", "SK",
	"SI", "ES", "SE", "CH", "UA", "GB", "VA", "FO", "GI", "GG", "JE", "IM",
	// Middle East
	"JO", "SA", "AE", "QA", "KW", "BH", "OM", "IQ", "SY", "LB", "IL", "PS", "YE",
	"TR", "IR",
	// Caucasus / Central Asia
	"AM", "AZ", "GE", "KZ", "UZ", "TM", "KG", "TJ", "AF",
	// Indian subcontinent
	"IN", "PK", "BD", "LK", "NP", "BT", "MV",
	// Africa
	"DZ", "AO", "BJ", "BW", "BF", "BI", "CM", "CV", "CF", "TD", "KM", "CG", "CD",
	"CI", "DJ", "EG", "GQ", "ER", "SZ", "ET", "GA", "GM", "GH", "GN", "GW", "KE",
	"LS", "LR", "LY", "MG", "MW", "ML", "MR", "MU", "MA", "MZ", "NA", "NE", "NG",
	"RW", "ST", "SN", "SC", "SL", "SO", "ZA", "SS", "SD", "TZ", "TG", "TN", "UG",
	"ZM", "ZW",
)

func toSet(codes ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	return set
}

// nearEurope reports whether the CloudFront viewer-country code is one whose
// nearest relay is the Frankfurt one. An empty or unknown code (a request that
// did not come through CloudFront, e.g. over Tor) is not.
func nearEurope(countryCode string) bool {
	_, ok := nearEuropeCountries[strings.ToUpper(strings.TrimSpace(countryCode))]
	return ok
}
