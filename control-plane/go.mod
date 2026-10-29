module github.com/routesphere-global/bonvoyage/control-plane

go 1.26.10

require (
	github.com/routesphere-global/bonvoyage/api/gen v0.0.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
)

replace github.com/routesphere-global/bonvoyage/api/gen => ../api/gen
