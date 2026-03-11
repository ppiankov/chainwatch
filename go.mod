module github.com/ppiankov/chainwatch

go 1.25.7

require (
	github.com/aws/aws-sdk-go-v2 v1.39.0
	github.com/aws/aws-sdk-go-v2/config v1.32.1
	github.com/aws/aws-sdk-go-v2/credentials v1.19.1
	github.com/aws/aws-sdk-go-v2/service/bedrockruntime v1.31.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/modelcontextprotocol/go-sdk v1.3.0
	github.com/ppiankov/neurorouter v0.2.0
	github.com/spf13/cobra v1.10.2
	google.golang.org/grpc v1.79.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

require (
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	modernc.org/sqlite v1.46.1
)

replace github.com/aws/aws-sdk-go-v2 => ./third_party/aws-sdk-go-v2

replace github.com/aws/aws-sdk-go-v2/config => ./third_party/aws-sdk-go-v2-config

replace github.com/aws/aws-sdk-go-v2/credentials => ./third_party/aws-sdk-go-v2-credentials

replace github.com/aws/aws-sdk-go-v2/service/bedrockruntime => ./third_party/aws-sdk-go-v2-service-bedrockruntime
