package netlinkd

import (
	"fmt"
	"net"
	"regexp"
	"sync"

	"github.com/apex/log"
	"github.com/google/nftables"
)

// nameRe restricts target names to a safe charset to avoid resolving unexpected
// set names.
var nameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// nftApplier applies messages to nftables sets directly over netlink.
type nftApplier struct {
	family     nftables.TableFamily
	table      string
	setPrefix  string
	setPrefix6 string

	mu sync.Mutex
}

// newNftApplier builds an nftApplier from the config.
func newNftApplier(cfg Config) *nftApplier {
	return &nftApplier{
		family:     familyFromString(cfg.Family),
		table:      cfg.Table,
		setPrefix:  cfg.SetPrefix,
		setPrefix6: cfg.SetPrefix6,
	}
}

// familyFromString maps a family flag value to the nftables.TableFamily
// constant. Unknown values fall back to inet.
func familyFromString(family string) nftables.TableFamily {
	switch family {
	case "ip":
		return nftables.TableFamilyIPv4
	case "ip6":
		return nftables.TableFamilyIPv6
	case "inet", "":
		return nftables.TableFamilyINet
	default:
		return nftables.TableFamilyINet
	}
}

// parseIPv4Elements converts a list of IPv4 address strings into nftables set
// elements, skipping and logging entries that are not valid IPv4 addresses.
func parseIPv4Elements(addrs []string) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			log.WithField("addr", a).Warn("skipping invalid ipv4 address")
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			log.WithField("addr", a).Warn("skipping non-ipv4 address")
			continue
		}
		elems = append(elems, nftables.SetElement{Key: v4})
	}
	return elems
}

// parseIPv6Elements converts a list of IPv6 address strings into nftables set
// elements, skipping and logging entries that are not valid IPv6 addresses.
func parseIPv6Elements(addrs []string) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			log.WithField("addr", a).Warn("skipping invalid ipv6 address")
			continue
		}
		// Reject IPv4 addresses: an IPv4 string also yields a 16-byte form.
		if ip.To4() != nil {
			log.WithField("addr", a).Warn("skipping non-ipv6 address")
			continue
		}
		v6 := ip.To16()
		if v6 == nil {
			log.WithField("addr", a).Warn("skipping non-ipv6 address")
			continue
		}
		elems = append(elems, nftables.SetElement{Key: v6})
	}
	return elems
}

// Apply resolves the target sets and adds the parsed addresses via netlink,
// mirroring the original `nft add element` behavior.
func (a *nftApplier) Apply(msg Message) error {
	if !nameRe.MatchString(msg.Name) {
		return fmt.Errorf("invalid target name %q", msg.Name)
	}

	v4Elems := parseIPv4Elements(msg.IPv4)
	v6Elems := parseIPv6Elements(msg.IPv6)

	if len(v4Elems) == 0 && len(v6Elems) == 0 {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open netlink conn: %w", err)
	}

	tbl := &nftables.Table{Family: a.family, Name: a.table}

	if len(v4Elems) > 0 {
		setName := a.setPrefix + msg.Name
		set, err := conn.GetSetByName(tbl, setName)
		if err != nil {
			return fmt.Errorf("lookup set %q: %w", setName, err)
		}
		if err := conn.SetAddElements(set, v4Elems); err != nil {
			return fmt.Errorf("add elements to set %q: %w", setName, err)
		}
	}

	if len(v6Elems) > 0 {
		setName := a.setPrefix6 + msg.Name
		set, err := conn.GetSetByName(tbl, setName)
		if err != nil {
			return fmt.Errorf("lookup set %q: %w", setName, err)
		}
		if err := conn.SetAddElements(set, v6Elems); err != nil {
			return fmt.Errorf("add elements to set %q: %w", setName, err)
		}
	}

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush netlink: %w", err)
	}

	return nil
}
