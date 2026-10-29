module github.com/routesphere-global/bonvoyage/control-plane

go 1.25.0

require (
	github.com/routesphere-global/bonvoyage/api/gen v0.0.0
	google.golang.org/grpc v1.70.0
	google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241202173237-19429a94021a // indirect
)

replace github.com/routesphere-global/bonvoyage/api/gen => ../api/gen
