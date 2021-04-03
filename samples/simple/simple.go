// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// simple demonstrates a simpler i3bar built using barista.
// Serves as a good starting point for building custom bars.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"barista.run"
	"barista.run/bar"
	"barista.run/base/click"
	"barista.run/base/watchers/netlink"
	"barista.run/colors"
	"barista.run/modules/battery"
	"barista.run/modules/clock"
	"barista.run/modules/cputemp"
	"barista.run/modules/media"
	"barista.run/modules/netspeed"
	"barista.run/modules/sysinfo"
	"barista.run/modules/volume"
	"barista.run/modules/volume/alsa"
	"barista.run/modules/weather"
	"barista.run/modules/weather/openweathermap"
	"barista.run/oauth"
	"barista.run/outputs"
	"barista.run/pango"
	"barista.run/pango/icons/fontawesome"
	"barista.run/pango/icons/material"
	"barista.run/pango/icons/mdi"
	"barista.run/pango/icons/typicons"

	colorful "github.com/lucasb-eyer/go-colorful"
	"github.com/martinlindhe/unit"
	keyring "github.com/zalando/go-keyring"
	"github.com/RobinUS2/golang-moving-average"
)

var spacer = pango.Text(" ").XXSmall()

func outputGroup(g *outputs.SegmentGroup) *outputs.SegmentGroup {
	return g.InnerSeparators(false).InnerPadding(5).Padding(12)
}

func truncate(in string, l int) string {
	if len([]rune(in)) <= l {
		return in
	}
	return string([]rune(in)[:l-1]) + "…"
}

func hms(d time.Duration) (h int, m int, s int) {
	h = int(d.Hours())
	m = int(d.Minutes()) % 60
	s = int(d.Seconds()) % 60
	return
}

var startTaskManager = click.RunLeft("lxtask")

func home(path string) string {
	usr, err := user.Current()
	if err != nil {
		panic(err)
	}
	return filepath.Join(usr.HomeDir, path)
}

type freegeoipResponse struct {
	Lat float64 `json:"latitude"`
	Lng float64 `json:"longitude"`
}

func whereami() (lat float64, lng float64, err error) {
	resp, err := http.Get("https://freegeoip.app/json/")
	if err != nil {
		return 0, 0, err
	}
	var res freegeoipResponse
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return 0, 0, err
	}
	return res.Lat, res.Lng, nil
}

type autoWeatherProvider struct{}

func (a autoWeatherProvider) GetWeather() (weather.Weather, error) {
	lat, lng, err := whereami()
	if err != nil {
		return weather.Weather{}, err
	}
	return openweathermap.
		New("%%OWM_API_KEY%%").
		Coords(lat, lng).
		GetWeather()
}

func setupOauthEncryption() error {
	const service = "barista-sample-bar"
	var username string
	if u, err := user.Current(); err == nil {
		username = u.Username
	} else {
		username = fmt.Sprintf("user-%d", os.Getuid())
	}
	var secretBytes []byte
	// IMPORTANT: The oauth tokens used by some modules are very sensitive, so
	// we encrypt them with a random key and store that random key using
	// libsecret (gnome-keyring or equivalent). If no secret provider is
	// available, there is no way to store tokens (since the version of
	// sample-bar used for setup-oauth will have a different key from the one
	// running in i3bar). See also https://github.com/zalando/go-keyring#linux.
	secret, err := keyring.Get(service, username)
	if err == nil {
		secretBytes, err = base64.RawURLEncoding.DecodeString(secret)
	}
	if err != nil {
		secretBytes = make([]byte, 64)
		_, err := rand.Read(secretBytes)
		if err != nil {
			return err
		}
		secret = base64.RawURLEncoding.EncodeToString(secretBytes)
		keyring.Set(service, username, secret)
	}
	oauth.SetEncryptionKey(secretBytes)
	return nil
}

var gsuiteOauthConfig = []byte(`{"installed": {
	"client_id":"%%GOOGLE_CLIENT_ID%%",
	"project_id":"i3-barista",
	"auth_uri":"https://accounts.google.com/o/oauth2/auth",
	"token_uri":"https://www.googleapis.com/oauth2/v3/token",
	"auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs",
	"client_secret":"%%GOOGLE_CLIENT_SECRET%%",
	"redirect_uris":["urn:ietf:wg:oauth:2.0:oob","http://localhost"]
}}`)

func main() {
	material.Load(home("src/material-design-icons"))
	mdi.Load(home("src/MaterialDesign-Webfont"))
	typicons.Load(home("src/typicons.font"))
	fontawesome.Load(home("src/Font-Awesome"))

	colors.LoadBarConfig()
	bg := colors.Scheme("background")
	fg := colors.Scheme("statusline")
	if fg != nil && bg != nil {
		iconColor := fg.Colorful().BlendHcl(bg.Colorful(), 0.5).Clamped()
		colors.Set("dim-icon", iconColor)
		_, _, v := fg.Colorful().Hsv()
		if v < 0.3 {
			v = 0.3
		}
		colors.Set("bad", colorful.Hcl(40, 1.0, v).Clamped())
		colors.Set("degraded", colorful.Hcl(90, 1.0, v).Clamped())
		colors.Set("good", colorful.Hcl(120, 1.0, v).Clamped())
	}

	if err := setupOauthEncryption(); err != nil {
		panic(fmt.Sprintf("Could not setup oauth token encryption: %v", err))
	}

	localtime := clock.Local().
		Output(time.Minute, func(now time.Time) bar.Output {
			return outputs.Pango(
				pango.Icon("far-clock").Color(colors.Scheme("dim-icon")),
				spacer,
				now.Format("02.01.2006 15:04"),
			).OnClick(click.RunLeft("gsimplecal"))
		})

	// Weather information comes from OpenWeatherMap.
	// https://openweathermap.org/api.
	wthr := weather.New(autoWeatherProvider{}).Output(func(w weather.Weather) bar.Output {
		iconName := ""
		switch w.Condition {
		case weather.Thunderstorm,
			weather.TropicalStorm,
			weather.Hurricane:
			iconName = "poo-storm"
		case weather.Drizzle,
			weather.Hail:
			iconName = "cloud-rain"
		case weather.Rain:
			iconName = "cloud-showers-heavy"
		case weather.Snow,
			weather.Sleet:
			iconName = "snowflake"
		case weather.Mist,
			weather.Smoke,
			weather.Whirls,
			weather.Haze,
			weather.Fog:
			iconName = "smog"
		case weather.Clear:
			if !w.Sunset.IsZero() && time.Now().After(w.Sunset) {
				iconName = "moon"
			} else {
				iconName = "sun"
			}
		case weather.PartlyCloudy:
			iconName = "cloud-sun"
		case weather.Cloudy, weather.Overcast:
			iconName = "cloud"
		case weather.Tornado,
			weather.Windy:
			iconName = "wind"
		}
		if iconName == "" {
			iconName = "exclamation-circle"
		}
		return outputs.Pango(
			pango.Icon("fa-"+iconName), spacer,
			pango.Textf("%.1f℃", w.Temperature.Celsius()),
			pango.Textf(" %s", w.Location).XSmall(),
		)
	})

	buildBattOutput := func(i battery.Info, disp *pango.Node) *bar.Segment {
		if i.Status == battery.Disconnected || i.Status == battery.Unknown {
			return nil
		}
		iconName := "battery"
		if i.Status == battery.Charging {
			iconName += "-charging"
		}
		tenth := i.RemainingPct() / 10
		switch {
		case tenth == 0:
			iconName += "-outline"
		case tenth < 10:
			iconName += fmt.Sprintf("-%d0", tenth)
		}
		out := outputs.Pango(pango.Icon("mdi-"+iconName), disp)
		switch {
		case i.RemainingPct() <= 5:
			out.Urgent(true)
		case i.RemainingPct() <= 15:
			out.Color(colors.Scheme("bad"))
		case i.RemainingPct() <= 25:
			out.Color(colors.Scheme("degraded"))
		}
		return out
	}
	var showBattPct, showBattTime func(battery.Info) bar.Output

	batt := battery.All()
	showBattPct = func(i battery.Info) bar.Output {
		out := buildBattOutput(i, pango.Textf("%d%%", i.RemainingPct()))
		if out == nil {
			return nil
		}
		return out.OnClick(click.Left(func() {
			batt.Output(showBattTime)
		}))
	}
	showBattTime = func(i battery.Info) bar.Output {
		rem := i.RemainingTime()
		out := buildBattOutput(i, pango.Textf(
			"%d:%02d", int(rem.Hours()), int(rem.Minutes())%60))
		if out == nil {
			return nil
		}
		return out.OnClick(click.Left(func() {
			batt.Output(showBattPct)
		}))
	}
	batt.Output(showBattPct)

	vol := volume.New(alsa.DefaultMixer()).Output(func(v volume.Volume) bar.Output {
		if v.Mute {
			return outputGroup(outputs.Group(
				pango.Icon("fa-volume-mute"),
				outputs.Text("MUT"),
			))
		}
		iconName := "off"
		pct := v.Pct()
		if pct > 66 {
			iconName = "up"
		} else if pct > 33 {
			iconName = "down"
		}

		return outputGroup(outputs.Group(
			pango.Icon("fa-volume-"+iconName),
			outputs.Textf("%2d%%", pct),
		))
	})

	loadAvg := sysinfo.New().Output(func(s sysinfo.Info) bar.Output {
		out := outputs.Pango(
			pango.Icon("fa-weight-hanging"),
			spacer,
			pango.Textf("%0.2f %0.2f", s.Loads[0], s.Loads[2]),
		)
		// Load averages are unusually high for a few minutes after boot.
		if s.Uptime < 10*time.Minute {
			// so don't add colours until 10 minutes after system start.
			return out
		}
		switch {
		case s.Loads[0] > 128, s.Loads[2] > 64:
			out.Urgent(true)
		case s.Loads[0] > 64, s.Loads[2] > 32:
			out.Color(colors.Scheme("bad"))
		case s.Loads[0] > 32, s.Loads[2] > 16:
			out.Color(colors.Scheme("degraded"))
		}
		out.OnClick(startTaskManager)
		return out
	})

	temp := cputemp.New().
		RefreshInterval(2 * time.Second).
		Output(func(temp unit.Temperature) bar.Output {
			out := outputs.Pango(
				pango.Icon("fa-microchip"), spacer,
				pango.Textf("%2d℃", int(temp.Celsius())),
			)
			switch {
			case temp.Celsius() > 90:
				out.Urgent(true)
			case temp.Celsius() > 70:
				out.Color(colors.Scheme("bad"))
			case temp.Celsius() > 60:
				out.Color(colors.Scheme("degraded"))
			}
			return out
		})

	sub := netlink.Any()
	iface := sub.Get().Name
	ips := sub.Get().IPs
	sub.Unsubscribe()
	maTx := movingaverage.New(5)
	maRx := movingaverage.New(5)
	net := netspeed.New(iface).
		RefreshInterval(time.Second / 2).
		Output(func(s netspeed.Speeds) bar.Output {
			maTx.Add(s.Tx.BitsPerSecond())
			maRx.Add(s.Rx.BitsPerSecond())

			txColor := colors.Hex("#fff")
			rxColor := colors.Hex("#fff")

			minActivityBits := 40000.0 // 5 KB

			if maTx.Avg() > minActivityBits {
				txColor = colors.Hex("#bfff00")
			}
			if maRx.Avg() > minActivityBits {
				rxColor = colors.Hex("#ff00ae")
			}

			group := outputs.Group(
				outputs.Pango(pango.Icon("fa-angle-up").Color(txColor)),
				outputs.Pango(pango.Icon("fa-angle-down").Color(rxColor)),
			)

			for _, ip := range ips {
				if len(ip) == 4 {
					group.Append(outputs.Pango(
						pango.Text(iface),
						pango.Textf(" %s", ip.String()).XSmall()),
					)
				}
			}

			return outputGroup(group).OnClick(click.RunLeft("nm-connection-editor"))
		})

	rhythmbox := media.Auto().
		Output(func(m media.Info) bar.Output {
			if m.PlaybackStatus == media.Stopped || m.PlaybackStatus == media.Disconnected {
				return nil
			}

			artist := truncate(m.Artist, 20)
			title := truncate(m.Title, 40-len(artist))
			if len(title) < 20 {
				artist = truncate(m.Artist, 40-len(title))
			}

			group := new(outputs.SegmentGroup)

			if m.Playing() {
				group.Append(outputs.Pango(pango.Icon("fa-pause")).Color(colors.Hex("#f70")).OnClick(click.Left(m.Pause)))
			} else {
				group.Append(outputs.Pango(pango.Icon("fa-play")).Color(colors.Hex("#f70")).OnClick(click.Left(m.Play)))
			}

			group.Append(outputs.Pango(pango.Icon("fa-step-forward")).Color(colors.Hex("#f70")).OnClick(click.Left(m.Next)))
			group.Append(outputs.Textf("%s · %s", title, artist).OnClick(nil))

			return outputGroup(group)
		})

	panic(barista.Run(
		rhythmbox,
		vol,
		net,
		temp,
		loadAvg,
		batt,
		wthr,
		localtime,
	))
}
