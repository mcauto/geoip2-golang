package geoip2_test

import (
	"math/rand"
	"net"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/geoip2-golang/origin"
	"github.com/stretchr/testify/assert"
)

func BenchmarkCityOrigin(b *testing.B) {
	b.Run("origin city", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-City-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			city, err := db.City(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, city)
			}
		}
	})
	b.Run("zero city", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-City-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			city, err := db.City(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, city)
			}
		}
	})
	b.Run("origin country", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-Country-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			country, err := db.Country(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, country)
			}
		}
	})
	b.Run("zero country", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-Country-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			country, err := db.Country(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, country)
			}
		}
	})
	b.Run("origin anonymous ip", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			anonIP, err := db.AnonymousIP(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, anonIP)
			}
		}
	})
	b.Run("zero anonymous ip", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-Anonymous-IP-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			anonIP, err := db.AnonymousIP(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, anonIP)
			}
		}
	})
	b.Run("origin asn", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoLite2-ASN-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			asn, err := db.ASN(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, asn)
			}
		}
	})
	b.Run("zero asn", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoLite2-ASN-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			asn, err := db.ASN(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, asn)
			}
		}
	})
	b.Run("origin connection type", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-Connection-Type-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			connType, err := db.ConnectionType(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, connType)
			}
		}
	})
	b.Run("zero connection type", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-Connection-Type-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			connType, err := db.ConnectionType(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, connType)
			}
		}
	})
	b.Run("origin domain", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-Domain-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			domain, err := db.Domain(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, domain)
			}
		}
	})
	b.Run("zero domain", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-Domain-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			domain, err := db.Domain(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, domain)
			}
		}
	})
	b.Run("origin isp", func(b *testing.B) {
		db, err := origin.Open("./test-data/test-data/GeoIP2-ISP-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			isp, err := db.ISP(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, isp)
			}
		}
	})
	b.Run("zero isp", func(b *testing.B) {
		db, err := geoip2.Open("./test-data/test-data/GeoIP2-ISP-Test.mmdb")
		if assert.NoError(b, err) {
			assert.NotNil(b, db)
		}
		defer db.Close()
		r := rand.New(rand.NewSource(0))
		ip := make(net.IP, 4)
		for i := 0; i < b.N; i++ {
			randomIPv4Address(r, ip)
			isp, err := db.ISP(ip)
			if assert.NoError(b, err) {
				assert.NotNil(b, isp)
			}
		}
	})
}

func randomIPv4Address(r *rand.Rand, ip net.IP) {
	num := r.Uint32()
	ip[0] = byte(num >> 24)
	ip[1] = byte(num >> 16)
	ip[2] = byte(num >> 8)
	ip[3] = byte(num)
}
