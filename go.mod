module qff

go 1.23.0

toolchain go1.24.5

require (
	github.com/google/nftables v0.0.0-00010101000000-000000000000
	github.com/gorilla/mux v1.8.1
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/prometheus/client_golang v1.19.1
	github.com/shirou/gopsutil/v3 v3.24.5
)

replace github.com/google/nftables => ../nftables

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250702063131-0f7746f74615 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)
