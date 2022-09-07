package web

import (
	"fmt"
	"github.com/fatih/structs"
	"log"
	"reflect"
	"strconv"
	"strings"
)

const (
	crlf = "\r\n"
)

const (
	SourceNTLM int = iota
	SourceSmartCard
	SourceCurrent
	SourceUserSelect
	SourceCookie
)

type RdpConnection struct {
	GatewayHostname          string `rdp:"gatewayhostname"`
	FullAddress              string `rdp:"full address"`
	AlternateFullAddress     string `rdp:"alternate full address"`
	Username                 string `rdp:"username"`
	Domain                   string `rdp:"domain"`
	GatewayCredentialSource  int    `rdp:"gatewaycredentialsource" default:"0"`
	GatewayCredentialMethode int    `rdp:"gatewayprofileusagemethod" default:"0"`
	GatewayUsageMethod       int    `rdp:"gatewayusagemethod" default:"0"`
	GatewayAccessToken       string `rdp:"gatewayaccesstoken"`
	PromptCredentialsOnce    bool   `rdp:"promptcredentialonce" default:"true"`
	AuthenticationLevel      int    `rdp:"authentication level" default:"3"`
	EnableCredSSPSupport     bool   `rdp:"enablecredsspsupport" default:"true"`
	EnableRdsAasAuth         bool   `rdp:"enablerdsaadauth" default:"false"`
	DisableConnectionSharing bool   `rdp:"disableconnectionsharing" default:"false"`
	AlternateShell           string `rdp:"alternate shell"`
}

type RdpSession struct {
	AutoReconnectionEnabled bool `rdp:"autoreconnectionenabled" default:"true"`
	BandwidthAutodetect     bool `rdp:"bandwidthautodetect" default:"true"`
	NetworkAutodetect       bool `rdp:"networkautodetect" default:"true"`
	Compression             bool `rdp:"compression" default:"true"`
	VideoPlaybackMode       bool `rdp:"videoplaybackmode" default:"true"`
	ConnectionType          int  `rdp:"connection type" default:"2"`
}

type RdpDeviceRedirect struct {
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
}

type RdpDisplay struct {
	UseMultimon               bool   `rdp:"use multimon" default:"false"`
	SelectedMonitors          string `rdp:"selectedmonitors"`
	MaximizeToCurrentDisplays bool   `rdp:"maximizetocurrentdisplays" default:"false"`
	SingleMonInWindowedMode   bool   `rdp:"singlemoninwindowedmode" default:"0"`
	ScreenModeId              int    `rdp:"screen mode id" default:"2"`
	SmartSizing               bool   `rdp:"smart sizing" default:"false"`
	DynamicResolution         bool   `rdp:"dynamic resolution" default:"true"`
	DesktopSizeId             int    `rdp:"desktop size id"`
	DesktopHeight             int    `rdp:"desktopheight"`
	DesktopWidth              int    `rdp:"desktopwidth"`
	DesktopScaleFactor        int    `rdp:"desktopscalefactor"`
	BitmapCacheSize           int    `rdp:"bitmapcachesize" default:"1500"`
}

type RdpRemoteApp struct {
	RemoteApplicationCmdLine  string `rdp:"remoteapplicationcmdline"`
	RemoteAppExpandWorkingDir bool   `rdp:"remoteapplicationexpandworkingdir" default:"true"`
	RemoteApplicationFile     string `rdp:"remoteapplicationfile" default:"true"`
	RemoteApplicationIcon     string `rdp:"remoteapplicationicon"`
	RemoteApplicationMode     bool   `rdp:"remoteapplicationmode" default:"true"`
	RemoteApplicationName     string `rdp:"remoteapplicationname"`
	RemoteApplicationProgram  string `rdp:"remoteapplicationprogram"`
}

type RdpBuilder struct {
	Connection     RdpConnection
	Session        RdpSession
	DeviceRedirect RdpDeviceRedirect
	Display        RdpDisplay
	RemoteApp      RdpRemoteApp
}

func NewRdp() *RdpBuilder {
	c := RdpConnection{}
	s := RdpSession{}
	dr := RdpDeviceRedirect{}
	disp := RdpDisplay{}
	ra := RdpRemoteApp{}

	initStruct(&c)
	initStruct(&s)
	initStruct(&dr)
	initStruct(&disp)
	initStruct(&ra)

	return &RdpBuilder{
		Connection:     c,
		Session:        s,
		DeviceRedirect: dr,
		Display:        disp,
		RemoteApp:      ra,
	}
}

func (rb *RdpBuilder) String() string {
	var sb strings.Builder

	addStructToString(rb.Connection, &sb)
	addStructToString(rb.Session, &sb)
	addStructToString(rb.DeviceRedirect, &sb)
	addStructToString(rb.Display, &sb)
	addStructToString(rb.RemoteApp, &sb)

	return sb.String()
}

func addStructToString(st interface{}, sb *strings.Builder) {
	s := structs.New(st)
	for _, f := range s.Fields() {
		if isZero(f) {
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
		sb.WriteString(crlf)
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

func initStruct(st interface{}) {
	s := structs.New(st)
	for _, f := range s.Fields() {
		t := f.Tag("default")
		if t == "" {
			continue
		}

		switch f.Kind() {
		case reflect.String:
			f.Set(t)
		case reflect.Int:
			i, err := strconv.Atoi(t)
			if err != nil {
				log.Fatalf("runtime error: default %s is not an integer", t)
			}
			f.Set(i)
		case reflect.Bool:
			b := false
			if t == "true" || t == "1" {
				b = true
			}
			err := f.Set(b)
			if err != nil {
				log.Fatalf("Cannot set bool field")
			}
		}
	}
}
