package miner

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
)

// Xmrig implements the miner interface for the xmrig miner, including
// xmrig-amd and xmrig-nvidia
// https://github.com/xmrig/xmrig
// https://github.com/xmrig/xmrig-amd
// https://github.com/xmrig/xmrig-nvidia
type Xmrig struct {
	Base
	name             string
	endpoint         string
	lastHashrate     float64
	resultStatsCache XmrigResponse
	isGPU            bool
}

// XmrigConfig is the config.json structure for Xmrig
// Generated with https://mholt.github.io/json-to-go/
type XmrigConfig struct {
	API             XmrigAPIConfig     `json:"api"`
	HTTP            XmrigHTTPConfig    `json:"http"`
	AutoSave        bool               `json:"autosave"`
	Background      bool               `json:"background"`
	Colors          bool               `json:"colors"`
	RandomX         XmrigRandomXConfig `json:"randomx"`
	CPU             XmrigCPUConfig     `json:"cpu"`
	OpenCl          XmrigOpenCLConfig  `json:"opencl"`
	Cuda            XmrigCudaConfig    `json:"cuda"`
	DonateLevel     int                `json:"donate-level"`
	DonateOverProxy int                `json:"donate-over-proxy"`
	LogFile         string             `json:"log-file"`
	Pools           []XmrigPoolConfig  `json:"pools"`
	//MaxCPUUsage uint8             `json:"max-cpu-usage"`
	PrintTime  int  `json:"print-time"`
	Retries    int  `json:"retries"`
	RetryPause int  `json:"retry-pause"`
	Syslog     bool `json:"syslog"`
	//Threads     uint16            `json:"threads"`
	UserAgent string `json:"user-agent"`
}

// XmrigPoolConfig contains the configuration for a pool in Xmrig
type XmrigPoolConfig struct {
	Algo           string      `json:"algo"`
	Coin           interface{} `json:"coin"`
	URL            string      `json:"url"`
	User           string      `json:"user"`
	Pass           string      `json:"pass"`
	RigID          interface{} `json:"rig-id"`
	Nicehash       bool        `json:"nicehash"`
	Keepalive      bool        `json:"keepalive"`
	Enabled        bool        `json:"enabled"`
	TLS            bool        `json:"tls"`
	TLSFingerprint interface{} `json:"tls-fingerprint"`
	Daemon         bool        `json:"daemon"`
	SelfSelect     bool        `json:"self-select"`
}

// XmrigAPIConfig contains the Xmrig API config
type XmrigAPIConfig struct {
	ID       string `json:"id"`
	WorkerID string `json:"worker-id"`
}

// XmrigHTTPConfig
type XmrigHTTPConfig struct {
	Enabled     bool        `json:"enabled"`
	Host        string      `json:"host"`
	Port        int         `json:"port"`
	AccessToken interface{} `json:"access-token"`
	Restricted  bool        `json:"restricted"`
}

// XmrigRandomX
type XmrigRandomXConfig struct {
	Init  int    `json:"init"`
	Mode  string `json:"mode"`
	Wrmsr bool   `json:"wrmsr"`
}

// XmrigCPU
type XmrigCPUConfig struct {
	Enabled   bool `json:"enabled"`
	Hugepages bool `json:"huge-pages"`
	HwAes     bool `json:"hw-aes"`
	//Priority       int     `json:"priority"`
	Priority       interface{} `json:"priority"`
	MemoryPool     bool        `json:"memory-pool"`
	Yield          bool        `json:"yield"`
	Asm            bool        `json:"asm"`
	Argon2         []int       `json:"argon2"`
	Argon2Impl     interface{} `json:"argon2-impl"`
	Cn             [][]int     `json:"cn"`
	CnHeavy        [][]int     `json:"cn-heavy"`
	CnLite         [][]int     `json:"cn-lite"`
	CnPico         [][]int     `json:"cn-pico"`
	CnGPU          []int       `json:"cn/gpu"`
	Rx             []int       `json:"rx"`
	RxArq          []int       `json:"rx/arq"`
	RxWow          []int       `json:"rx/wow"`
	RandomXEpic    []int       `json:"randomx/epic"`
	RandomXProgPOW []int       `json:"randomx/progpow"`
	RandomXCuckoo  []int       `json:"randomx/cuckoo"`
	Cn0            bool        `json:"cn/0"`
	CnLite0        bool        `json:"cn-lite/0"`
}

// XmrigOpenCL
type XmrigOpenCLConfig struct {
	Enabled  bool        `json:"enabled"`
	Cache    bool        `json:"cache"`
	Loader   interface{} `json:"loader"`
	Platform string      `json:"platform"`
}

// XmrigCuda
type XmrigCudaConfig struct {
	Enabled bool        `json:"enabled"`
	Loader  interface{} `json:"loader"`
}

// XmrigResponse contains the data from xmrig API
// Generated with https://mholt.github.io/json-to-go/
type XmrigResponse struct {
	ID         string `json:"id"`
	WorkerID   string `json:"worker_id"`
	Uptime     int    `json:"uptime"`
	Restricted bool   `json:"restricted"`
	Resources  struct {
		Memory struct {
			Free              int `json:"free"`
			Total             int `json:"total"`
			ResidentSetMemory int `json:"resident_set_memory"`
		} `json:"memory"`
		LoadAverage     []float64 `json:"load_average"`
		HardConcurrency int       `json:"hardware_concurrency"`
	} `json:"resources"`
	Features []string `json:"features"`
	Results  struct {
		DiffCurrent int      `json:"diff_current"`
		SharesGood  int      `json:"shares_good"`
		SharesTotal int      `json:"shares_total"`
		AvgTime     int      `json:"avg_time"`
		HashesTotal int      `json:"hashes_total"`
		Best        []int    `json:"best"`
		ErrorLog    []string `json:"error_log"`
	} `json:"results"`
	Algo       string `json:"algo"`
	Connection struct {
		Pool     string   `json:"pool"`
		IP       string   `json:"ip"`
		Uptime   int      `json:"uptime"`
		Ping     int      `json:"ping"`
		Failures int      `json:"failures"`
		ErrorLog []string `json:"error_log"`
	} `json:"connection"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	UA      string `json:"ua"`
	CPU     struct {
		Brand    string `json:"brand"`
		Aes      bool   `json:"aes"`
		Avx2     bool   `json:"avx2"`
		X64      bool   `json:"x64"`
		L2       int    `json:"l2"`
		L3       int    `json:"l3"`
		Cores    int    `json:"cores"`
		Threads  int    `json:"threads"`
		Packages int    `json:"Packages"`
		Nodes    int    `json:"nodes"`
		BackEnd  string `json:"backend"`
		Assembly string `json:"assembly"`
		Sockets  int    `json:"sockets"`
	} `json:"cpu"`
	DonateLevel int      `json:"donate_level"`
	Pause       bool     `json:"pause"`
	Algorithms  []string `json:"algorithms"`
	Hashrate    struct {
		Total   []float64   `json:"total"`
		Highest float64     `json:"highest"`
		Threads [][]float64 `json:"threads"`
	} `json:"hashrate"`
	Hugepages bool `json:"hugepages"`
}

// NewXmrig creates a new xmrig miner instance
func NewXmrig(config Config) (*Xmrig, error) {

	endpoint := config.Endpoint
	if endpoint == "" {
		endpoint = "http://127.0.0.1:16000"
	}

	miner := Xmrig{
		// We've switched to our own miner in V4, xtlrig, but I'm keeping
		// everything else xmrig for clarity
		name:     "epic-xmrig",
		endpoint: endpoint,
	}
	// xmrig appends either nvidia or amd to the miner if it's GPU only
	// just make sure that it's not the platform name containing amd64
	if (strings.Contains(config.Path, "nvidia") ||
		strings.Contains(config.Path, "amd")) &&
		strings.Contains(config.Path, "amd64") == false {
		miner.isGPU = true
		miner.name += "-gpu"
	}
	miner.Base.executableName = filepath.Base(config.Path)
	miner.Base.executablePath = filepath.Dir(config.Path)

	return &miner, nil
}

// WriteConfig writes the miner's configuration in the xmrig format
func (miner *Xmrig) WriteConfig(
	poolEndpoint string,
	walletAddress string,
	processingConfig ProcessingConfig) error {

	var err error
	var configBytes []byte
	if miner != nil {
		defaultConfig := miner.createConfig(
			poolEndpoint,
			walletAddress,
			processingConfig)
		configBytes, err = json.Marshal(defaultConfig)
		if err != nil {
			return err
		}
	}

	err = ioutil.WriteFile(
		filepath.Join(miner.Base.executablePath, "config.json"),
		configBytes,
		0644)
	if err != nil {
		return err
	}
	// Reset hashrate
	miner.lastHashrate = 0.00
	return nil
}

// GetProcessingConfig returns the current miner processing config
// TODO: Currently only CPU threads, extend this to full CPU/GPU config
func (miner *Xmrig) GetProcessingConfig() ProcessingConfig {

	configBytes, err := ioutil.ReadFile(
		filepath.Join(miner.Base.executablePath, "config.json"))
	if err != nil {
		return ProcessingConfig{}
	}

	// xmrig's threads field is not an int when it's GPU only so we need to use
	// a defferent config structure
	/*if miner.isGPU {
		var config XmrigGPUConfig
		err = json.Unmarshal(configBytes, &config)
		if err != nil {
			return ProcessingConfig{}
		}
		return ProcessingConfig{
			MaxUsage:   config.MaxCPUUsage,
			Threads:    uint16(len(miner.resultStatsCache.Hashrate.Threads)),
			MaxThreads: uint16(runtime.NumCPU()),
			Type:       miner.name,
		}
	}*/

	var config XmrigConfig
	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return ProcessingConfig{}
	}
	return ProcessingConfig{
		//MaxUsage:   config.MaxCPUUsage,
		Threads: uint16(len(miner.resultStatsCache.Hashrate.Threads)),
		//MaxThreads: uint16(runtime.NumCPU()),
		Type: miner.name,
	}
}

func makeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

// GetName returns the name of the miner
func (miner *Xmrig) GetName() string {
	return miner.name
}

// GetLastHashrate returns the last reported hashrate
func (miner *Xmrig) GetLastHashrate() float64 {
	return miner.lastHashrate
}

// GetStats returns the current miner stats
func (miner *Xmrig) GetStats() (Stats, error) {
	var stats Stats
	var xmrigStats XmrigResponse
	var bearer = "Bearer " + "test"         // TODO: Get this from config
	var url = miner.endpoint + "/1/summary" // Same here, check if /1/ is miner ID
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	//resp, err := http.Get(miner.endpoint)
	if err != nil {
		return stats, err
	}
	err = json.NewDecoder(resp.Body).Decode(&xmrigStats)
	if err != nil {
		return stats, err
	}

	var hashrate float64
	if len(xmrigStats.Hashrate.Total) > 0 {
		hashrate = xmrigStats.Hashrate.Total[0]
	}
	miner.lastHashrate = hashrate

	var errors []string
	/*
		TODO: I noticed errors are not reported in the xmrig API. To replicate,
		use an invalid Torque address with a pool that checks the address. In
		the command line you'll notice errors printed, but not added in the API.
		ApiState.cpp::getConnection and getResults functions might give some clues
		to getting it fixed.
		Issue reported: https://github.com/xmrig/xmrig/issues/589
	*/
	/*
		if len(xmrigStats.Connection.ErrorLog) > 0 {
			for _, err := range xmrigStats.Connection.ErrorLog {
				errors = append(errors, fmt.Sprintf("%s",
					err.Text,
				))
			}
		}
		if len(xmrigStats.Results.ErrorLog) > 0 {
			for _, err := range xmrigStats.Results.ErrorLog {
				errors = append(errors, fmt.Sprintf("(%d) %s",
					err.Count,
					err.Text,
				))
			}
		}
	*/
	stats = Stats{
		Hashrate:          hashrate,
		HashrateHuman:     HumanizeHashrate(hashrate),
		CurrentDifficulty: xmrigStats.Results.DiffCurrent,
		Uptime:            xmrigStats.Connection.Uptime,
		UptimeHuman:       HumanizeTime(xmrigStats.Connection.Uptime),
		SharesGood:        xmrigStats.Results.SharesGood,
		SharesBad:         xmrigStats.Results.SharesTotal - xmrigStats.Results.SharesGood,
		Errors:            errors,
	}
	miner.resultStatsCache = xmrigStats
	return stats, nil
}

//GetCPUCores and return an array representing each core
func GetCPUCores() []int {
	CPUNumber := int(runtime.NumCPU() / 2)
	RandomXCPUCores := makeRange(0, CPUNumber-1)
	return RandomXCPUCores
}

// createConfig returns creates the config for Xmrig
func (miner *Xmrig) createConfig(
	poolEndpoint string,
	walletAddress string,
	processingConfig ProcessingConfig) XmrigConfig {

	//runInBackground := true
	// On Mac OSX xmrig doesn't run is we fork the process to the background and
	// xmrig forks to the background again
	// Seems like xmrig doesn't like running GPU in the background
	/*if runtime.GOOS == "darwin" || miner.isGPU {
		runInBackground = false
	}*/

	CPUCores := GetCPUCores()

	config := XmrigConfig{
		API: XmrigAPIConfig{
			ID:       "1",
			WorkerID: "0",
		},
		HTTP: XmrigHTTPConfig{
			Enabled:     true,
			Host:        "127.0.0.1",
			Port:        16000,
			AccessToken: "test",
			Restricted:  true,
		},
		AutoSave:   true,
		Background: false,
		//Background: runInBackground,
		Colors: true,
		RandomX: XmrigRandomXConfig{
			Init:  1,
			Mode:  "auto",
			Wrmsr: true,
		},
		CPU: XmrigCPUConfig{
			Enabled:    true,
			Hugepages:  true,
			HwAes:      true,
			Priority:   nil,
			MemoryPool: true,
			Yield:      true,
			Asm:        false,
			Argon2:     []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			Argon2Impl: nil,
			Cn: [][]int{
				{1, 0},
				{1, 2},
				{1, 4},
				{1, 6},
				{1, 8},
			},
			CnHeavy: [][]int{
				{1, 0},
				{1, 2},
			},
			CnLite: [][]int{
				{1, 0},
				{1, 2},
				{1, 4},
				{1, 6},
				{1, 8},
				{1, 10},
				{1, 1},
				{1, 3},
				{1, 5},
			},
			CnPico: [][]int{
				{2, 0},
				{2, 1},
				{2, 2},
				{2, 3},
				{2, 4},
				{2, 5},
				{2, 6},
				{2, 7},
				{2, 8},
				{2, 9},
				{2, 10},
				{2, 11},
			},
			CnGPU:       []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			Rx:          []int{0, 2},
			RxArq:       []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			RxWow:       []int{0, 2, 4, 6, 8, 10, 1, 3, 5},
			RandomXEpic: CPUCores,
			//RandomXEpic:    []int{0, 1, 2, 3},
			RandomXProgPOW: []int{0},
			RandomXCuckoo:  []int{0},
			Cn0:            false,
			CnLite0:        false,
		},
		OpenCl: XmrigOpenCLConfig{
			Enabled:  false,
			Cache:    true,
			Loader:   nil,
			Platform: "AMD",
		},
		Cuda: XmrigCudaConfig{
			Enabled: false,
			Loader:  nil,
		},
		DonateLevel:     1,
		DonateOverProxy: 0,
		LogFile:         "epic-xmrig.log",
		//Threads:     processingConfig.Threads,
		Pools: []XmrigPoolConfig{
			{
				Algo:           "randomx/epic",
				Coin:           nil,
				URL:            poolEndpoint,
				User:           walletAddress,
				Pass:           "x",
				RigID:          nil,
				Nicehash:       false,
				Keepalive:      true,
				Enabled:        true,
				TLS:            false,
				TLSFingerprint: nil,
				Daemon:         false,
				SelfSelect:     false,
			},
		},
		PrintTime:  20,
		Retries:    100,
		RetryPause: 5,
		Syslog:     false,
		UserAgent:  "xmrig/v-epic-0.0.1",
	}

	return config
}
