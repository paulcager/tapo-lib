package tapo

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"
)

type Session struct {
	timestamp time.Time
	address   string
	username  string
	password  string
	private   *rsa.PrivateKey
	public    *rsa.PublicKey
	aesKey    []byte
	aesIv     []byte
	cookies   []*http.Cookie
	Client    *http.Client
	token     string
}

func NewSession(address string, username string, password string) (*Session, error) {
	private, public, err := generateKeys()
	if err != nil {
		return nil, err
	}

	sess := &Session{
		Client:   http.DefaultClient,
		address:  address,
		username: username,
		password: password,
		private:  private,
		public:   public,
	}

	return sess, nil
}

func (session *Session) Invalidate() {
	session.cookies = nil
	session.timestamp = time.Time{}
	session.token = ""
}

type DeviceInfo struct {
	DeviceID           string  `json:"device_id"`
	FwVer              string  `json:"fw_ver"`
	HwVer              string  `json:"hw_ver"`
	Type               string  `json:"type"`
	Model              string  `json:"model"`
	Mac                string  `json:"mac"`
	HwID               string  `json:"hw_id"`
	FwID               string  `json:"fw_id"`
	OemID              string  `json:"oem_id"`
	IP                 string  `json:"ip"`
	TimeDiff           int     `json:"time_diff"`
	Ssid               string  `json:"ssid"`
	Rssi               int     `json:"rssi"`
	SignalLevel        int     `json:"signal_level"`
	Latitude           float64 `json:"latitude"`
	Longitude          float64 `json:"longitude"`
	Lang               string  `json:"lang"`
	Avatar             string  `json:"avatar"`
	Region             string  `json:"region"`
	Specs              string  `json:"specs"`
	Nickname           string  `json:"nickname"`
	HasSetLocationInfo bool    `json:"has_set_location_info"`
	DeviceOn           bool    `json:"device_on"`
	OnTime             float64 `json:"on_time"`
	DefaultStates      struct {
		Type  string `json:"type"`
		State struct {
		} `json:"state"`
	} `json:"default_states"`
	Overheated            bool   `json:"overheated"`
	PowerProtectionStatus string `json:"power_protection_status"`
}

type EnergyUsage struct {
	TodayRuntimeMins       int    `json:"today_runtime"`
	MonthRuntimeMins       int    `json:"month_runtime"`
	TodayEnergyWattHours   int    `json:"today_energy"`
	MonthEnergyWattHours   int    `json:"month_energy"`
	LocalTime              string `json:"local_time"`
	ElectricityCharge      []int  `json:"electricity_charge"`
	CurrentPowerMilliWatts int    `json:"current_power"`
}

func (session *Session) Switch(on bool) error {
	type Reply struct {
		ErrorCode int `json:"error_code,omitempty"`
	}
	reply := Reply{}
	err := session.Post(message{Method: "set_device_info", Params: switchState{DeviceOn: on}}, &reply)
	if err == nil && reply.ErrorCode != 0 {
		err = fmt.Errorf("device replied %+v", reply)
	}
	return err
}

func (session *Session) GetDeviceInfo() (*DeviceInfo, error) {
	resp := struct {
		Result    DeviceInfo `json:"result"`
		ErrorCode int        `json:"error_code"`
	}{}

	err := session.Post(message{Method: "get_device_info"}, &resp)
	return &resp.Result, err
}

func (session *Session) GetEnergyUsage() (*EnergyUsage, error) {
	resp := struct {
		Result    EnergyUsage `json:"result"`
		ErrorCode int         `json:"error_code"`
	}{}

	err := session.Post(message{Method: "get_energy_usage"}, &resp)
	return &resp.Result, err
}

func (session *Session) Post(body interface{}, response interface{}) error {
	if session.requiresHandshake() {
		session.Invalidate()

		if err := session.handshake(); err != nil {
			return err
		}
		if err := session.login(); err != nil {
			return err
		}
	}

	return session.doPost(body, response)
}
