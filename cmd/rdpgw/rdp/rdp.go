package rdp

import (
	"errors"
	"fmt"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/rdp/koanf/parsers/rdp"
	"github.com/fatih/structs"
	"github.com/go-viper/mapstructure/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"log"
	"reflect"
	"strconv"
	"strings"
)

const (
	CRLF = "\r\n"
)

const (
	SourceNTLM int = iota
	SourceSmartCard
	SourceCurrent
	SourceBasic
	SourceUserSelect
	SourceCookie
)

type RdpSettings struct {
	AllowFontSmoothing                    bool   `rdp:"allow font smoothing" default:"0"`
	AllowDesktopComposition               bool   `rdp:"allow desktop composition" default:"0"`
	DisableFullWindowDrag                 bool   `rdp:"disable full window drag" default:"0"`
	DisableMenuAnims                      bool   `rdp:"disable menu anims" default:"0"`
	DisableThemes                         bool   `rdp:"disable themes" default:"0"`
	DisableCursorSetting                  bool   `rdp:"disable cursor setting" default:"0"`
	GatewayHostname                       string `rdp:"gatewayhostname"`
	FullAddress                           string `rdp:"full address"`
	AlternateFullAddress                  string `rdp:"alternate full address"`
	Username                              string `rdp:"username"`
	Domain                                string `rdp:"domain"`
	GatewayCredentialsSource              int    `rdp:"gatewaycredentialssource" default:"0"`
	GatewayCredentialMethod               int    `rdp:"gatewayprofileusagemethod" default:"0"`
	GatewayUsageMethod                    int    `rdp:"gatewayusagemethod" default:"0"`
	GatewayAccessToken                    string `rdp:"gatewayaccesstoken"`
	PromptCredentialsOnce                 bool   `rdp:"promptcredentialonce" default:"true"`
	AuthenticationLevel                   int    `rdp:"authentication level" default:"3"`
	EnableCredSSPSupport                  bool   `rdp:"enablecredsspsupport" default:"true"`
	EnableRdsAasAuth                      bool   `rdp:"enablerdsaadauth" default:"false"`
	DisableConnectionSharing              bool   `rdp:"disableconnectionsharing" default:"false"`
	AlternateShell                        string `rdp:"alternate shell"`
	AutoReconnectionEnabled               bool   `rdp:"autoreconnection enabled" default:"true"`
	BandwidthAutodetect                   bool   `rdp:"bandwidthautodetect" default:"true"`
	NetworkAutodetect                     bool   `rdp:"networkautodetect" default:"true"`
	Compression                           bool   `rdp:"compression" default:"true"`
	VideoPlaybackMode                     bool   `rdp:"videoplaybackmode" default:"true"`
	ConnectionType                        int    `rdp:"connection type" default:"2"`
	AudioCaptureMode                      bool   `rdp:"audiocapturemode" default:"false"`
	EncodeRedirectedVideoCapture          bool   `rdp:"encode redirected video capture" default:"true"`
	RedirectedVideoCaptureEncodingQuality int    `rdp:"redirected video capture encoding quality" default:"0"`
	AudioMode                             int    `rdp:"audiomode" default:"0"`
	CameraStoreRedirect                   string `rdp:"camerastoredirect" default:"false"`
	DeviceStoreRedirect                   string `rdp:"devicestoredirect" default:"false"`
	DriveStoreRedirect                    string `rdp:"drivestoredirect" default:"false"`
	KeyboardHook                          int    `rdp:"keyboardhook" default:"2"`
	RedirectClipboard                     bool   `rdp:"redirectclipboard" default:"true"`
	RedirectComPorts                      bool   `rdp:"redirectcomports" default:"false"`
	RedirectLocation                      bool   `rdp:"redirectlocation" default:"false"`
	RedirectPrinters                      bool   `rdp:"redirectprinters" default:"true"`
	RedirectSmartcards                    bool   `rdp:"redirectsmartcards" default:"true"`
	RedirectWebAuthn                      bool   `rdp:"redirectwebauthn" default:"true"`
	UsbDeviceStoRedirect                  string `rdp:"usbdevicestoredirect"`
	UseMultimon                           bool   `rdp:"use multimon" default:"false"`
	SelectedMonitors                      string `rdp:"selectedmonitors"`
	MaximizeToCurrentDisplays             bool   `rdp:"maximizetocurrentdisplays" default:"false"`
	SingleMonInWindowedMode               bool   `rdp:"singlemoninwindowedmode" default:"0"`
	ScreenModeId                          int    `rdp:"screen mode id" default:"2"`
	SmartSizing                           bool   `rdp:"smart sizing" default:"false"`
	DynamicResolution                     bool   `rdp:"dynamic resolution" default:"true"`
	DesktopSizeId                         int    `rdp:"desktop size id"`
	DesktopHeight                         int    `rdp:"desktopheight"`
	DesktopWidth                          int    `rdp:"desktopwidth"`
	DesktopScaleFactor                    int    `rdp:"desktopscalefactor"`
	BitmapCacheSize                       int    `rdp:"bitmapcachesize" default:"1500"`
	BitmapCachePersistEnable              bool   `rdp:"bitmapcachepersistenable" default:"true"`
	RemoteApplicationCmdLine              string `rdp:"remoteapplicationcmdline"`
	RemoteAppExpandWorkingDir             bool   `rdp:"remoteapplicationexpandworkingdir" default:"true"`
	RemoteApplicationFile                 string `rdp:"remoteapplicationfile" default:"true"`
	RemoteApplicationIcon                 string `rdp:"remoteapplicationicon"`
	RemoteApplicationMode                 bool   `rdp:"remoteapplicationmode" default:"false"`
	RemoteApplicationName                 string `rdp:"remoteapplicationname"`
	RemoteApplicationProgram              string `rdp:"remoteapplicationprogram"`
}

type Builder struct {
	Settings RdpSettings
	Metadata mapstructure.Metadata
	forced   map[string]struct{}
}

func NewBuilder() *Builder {
	c := RdpSettings{}

	initStruct(&c)

	return &Builder{
		Settings: c,
		Metadata: mapstructure.Metadata{},
	}
}

func NewBuilderFromFile(filename string) (*Builder, error) {
	c := RdpSettings{}
	initStruct(&c)
	metadata := mapstructure.Metadata{}

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           &c,
		Metadata:         &metadata,
		WeaklyTypedInput: true,
	}

	var k = koanf.New(".")
	if err := k.Load(file.Provider(filename), rdp.Parser()); err != nil {
		return nil, err
	}
	t := koanf.UnmarshalConf{Tag: "rdp", DecoderConfig: decoderConfig}

	if err := k.UnmarshalWithConf("", &c, t); err != nil {
		return nil, err
	}
	return &Builder{
		Settings: c,
		Metadata: metadata,
	}, nil
}

func (rb *Builder) String() string {
	var sb strings.Builder

	rb.addStructToString(rb.Settings, &sb)

	return sb.String()
}

// NormalizeRdpKey returns the canonical, URL-friendly form of an rdp tag
// (lowercase, no whitespace). Used to look up fields by query parameter name
// and to compare entries in the operator-supplied allow-list. For example,
// "use multimon", "Use Multimon" and "usemultimon" all normalize to
// "usemultimon".
func NormalizeRdpKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, " ", "")
}

// ApplyOverrides applies a set of caller-supplied RDP option overrides onto
// the Builder's settings. Each input key is normalized via NormalizeRdpKey and
// matched against the rdp struct tags of RdpSettings. Keys that do not match
// any field are ignored (so passing the entire request query is safe). Keys
// that match a field but are not present in allowed return an error: the
// allow-list is opt-in by design and empty by default.
//
// Values are validated against the field's Go type: bools accept 0/1 or
// true/false; ints must parse as base-10 integers; strings are taken
// verbatim. Overridden fields are tracked so they always serialize, even when
// the new value equals the field's default.
func (rb *Builder) ApplyOverrides(values map[string][]string, allowed []string) error {
	if len(values) == 0 {
		return nil
	}

	allow := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		allow[NormalizeRdpKey(k)] = struct{}{}
	}

	s := structs.New(&rb.Settings)
	byKey := make(map[string]*structs.Field, len(s.Fields()))
	for _, f := range s.Fields() {
		tag := f.Tag("rdp")
		if tag == "" {
			continue
		}
		byKey[NormalizeRdpKey(tag)] = f
	}

	if rb.forced == nil {
		rb.forced = make(map[string]struct{})
	}

	for k, vs := range values {
		nk := NormalizeRdpKey(k)
		f, ok := byKey[nk]
		if !ok {
			continue
		}
		if _, ok := allow[nk]; !ok {
			return fmt.Errorf("rdp option %q is not allowed to be overridden", k)
		}
		if len(vs) == 0 {
			continue
		}
		v := strings.TrimSpace(vs[0])
		if v == "" {
			return fmt.Errorf("rdp option %q has empty value", k)
		}
		if err := setRdpFieldFromString(f, v); err != nil {
			return fmt.Errorf("invalid value for rdp option %q: %w", k, err)
		}
		rb.forced[f.Name()] = struct{}{}
	}
	return nil
}

func (rb *Builder) isForced(f *structs.Field) bool {
	if rb.forced == nil {
		return false
	}
	_, ok := rb.forced[f.Name()]
	return ok
}

func (rb *Builder) addStructToString(st interface{}, sb *strings.Builder) {
	s := structs.New(st)
	for _, f := range s.Fields() {
		if isZero(f) && !isSet(f, rb.Metadata) && !rb.isForced(f) {
			continue
		}
		sb.WriteString(f.Tag("rdp"))
		sb.WriteString(":")

		switch f.Kind() {
		case reflect.String:
			sb.WriteString("s:")
			sb.WriteString(f.Value().(string))
		case reflect.Int:
			sb.WriteString("i:")
			fmt.Fprintf(sb, "%d", f.Value())
		case reflect.Bool:
			sb.WriteString("i:")
			if f.Value().(bool) {
				sb.WriteString("1")
			} else {
				sb.WriteString("0")

			}
		}
		sb.WriteString(CRLF)
	}
}

func isZero(f *structs.Field) bool {
	t := f.Tag("default")
	if t == "" {
		return f.IsZero()
	}

	switch f.Kind() {
	case reflect.String:
		if f.Value().(string) != t {
			return false
		}
		return true
	case reflect.Int:
		i, err := strconv.Atoi(t)
		if err != nil {
			log.Fatalf("runtime error: default %s is not an integer", t)
		}
		if f.Value().(int) != i {
			return false
		}
		return true
	case reflect.Bool:
		b := false
		if t == "true" || t == "1" {
			b = true
		}
		if f.Value().(bool) != b {
			return false
		}
		return true
	}

	return f.IsZero()
}

func isSet(f *structs.Field, metadata mapstructure.Metadata) bool {
	for _, v := range metadata.Unset {
		if v == f.Name() {
			log.Printf("field %s is unset", f.Name())
			return true
		}
	}
	return false
}

func initStruct(st interface{}) {
	s := structs.New(st)
	for _, f := range s.Fields() {
		t := f.Tag("default")
		if t == "" {
			continue
		}

		err := setVariable(f, t)
		if err != nil {
			log.Fatalf("cannot init rdp struct: %s", err)
		}
	}
}

func setVariable(f *structs.Field, v string) error {
	switch f.Kind() {
	case reflect.String:
		return f.Set(v)
	case reflect.Int:
		i, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		return f.Set(i)
	case reflect.Bool:
		b := false
		if v == "true" || v == "1" {
			b = true
		}
		return f.Set(b)
	default:
		return errors.New("invalid field type")
	}
}

func setRdpFieldFromString(f *structs.Field, v string) error {
	switch f.Kind() {
	case reflect.String:
		return f.Set(v)
	case reflect.Int:
		i, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("expected integer, got %q", v)
		}
		return f.Set(i)
	case reflect.Bool:
		switch strings.ToLower(v) {
		case "0", "false":
			return f.Set(false)
		case "1", "true":
			return f.Set(true)
		default:
			return fmt.Errorf("expected 0/1 or true/false, got %q", v)
		}
	default:
		return fmt.Errorf("unsupported rdp field kind %s", f.Kind())
	}
}
