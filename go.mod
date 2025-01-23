module github.com/kadirbelkuyu/DPI-bypass

go 1.22

toolchain go1.23.1

require (
    github.com/google/gopacket v1.1.19
    github.com/spf13/cobra v1.8.1
    github.com/spf13/viper v1.19.0
    go.uber.org/ratelimit v0.3.1
    go.uber.org/zap v1.27.0
    google.golang.org/genproto v0.0.0-20250122153221-138b5a5a4fd4
)

replace google.golang.org/genproto v0.0.0-20180817151627-c66870c02cf8 => google.golang.org/genproto v0.0.0-20250122153221-138b5a5a4fd4

require (
    github.com/benbjohnson/clock v1.3.5 // indirect
    github.com/fsnotify/fsnotify v1.8.0 // indirect
    github.com/hashicorp/hcl v1.0.0 // indirect
    github.com/inconshreveable/mousetrap v1.1.0 // indirect
    github.com/magiconair/properties v1.8.9 // indirect
    github.com/mitchellh/mapstructure v1.5.0 // indirect
    github.com/pelletier/go-toml/v2 v2.2.3 // indirect
    github.com/sagikazarmark/locafero v0.4.0 // indirect
    github.com/sagikazarmark/slog-shim v0.1.0 // indirect
    github.com/sourcegraph/conc v0.3.0 // indirect
    github.com/spf13/afero v1.12.0 // indirect
    github.com/spf13/cast v1.7.1 // indirect
    github.com/spf13/jwalterweatherman v1.1.0 // indirect
    github.com/spf13/pflag v1.0.5 // indirect
    github.com/subosito/gotenv v1.6.0 // indirect
    go.uber.org/atomic v1.11.0 // indirect
    go.uber.org/multierr v1.11.0 // indirect
    golang.org/x/exp v0.0.0-20230905200255-921286631fa9 // indirect
    golang.org/x/sys v0.29.0 // indirect
    golang.org/x/text v0.21.0 // indirect
    gopkg.in/ini.v1 v1.67.0 // indirect
    gopkg.in/yaml.v3 v3.0.1 // indirect
)
