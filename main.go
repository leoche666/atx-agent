package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"github.com/codeskyblue/kexec"
	"github.com/franela/goreq"
	"github.com/gorilla/websocket"
	"github.com/openatx/androidutils"
	"github.com/openatx/atx-agent/cmdctrl"
	"github.com/pkg/errors"
	"github.com/gorilla/mux"
)

var (
	service     = cmdctrl.New()
	downManager = newDownloadManager()
	upgrader    = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// singleFight for http request
// - minicap
// - minitouch
var muxMutex = sync.Mutex{}
var muxLocks = make(map[string]bool)
var muxConns = make(map[string]*websocket.Conn)

func singleFightWrap(handleFunc func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		muxMutex.Lock()
		if _, ok := muxLocks[r.RequestURI]; ok {
			muxMutex.Unlock()
			log.Println("singlefight conflict", r.RequestURI)
			http.Error(w, "singlefight conflicts", http.StatusTooManyRequests) // code: 429
			return
		}
		muxLocks[r.RequestURI] = true
		muxMutex.Unlock()

		handleFunc(w, r) // handle requests

		muxMutex.Lock()
		delete(muxLocks, r.RequestURI)
		muxMutex.Unlock()
	}
}

func singleFightNewerWebsocket(handleFunc func(http.ResponseWriter, *http.Request, *websocket.Conn)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		muxMutex.Lock()
		if oldWs, ok := muxConns[r.RequestURI]; ok {
			oldWs.Close()
			delete(muxConns, r.RequestURI)
		}

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			http.Error(w, "websocket upgrade error", 500)
			muxMutex.Unlock()
			return
		}
		muxConns[r.RequestURI] = wsConn
		muxMutex.Unlock()

		handleFunc(w, r, wsConn) // handle request

		muxMutex.Lock()
		if muxConns[r.RequestURI] == wsConn { // release connection
			delete(muxConns, r.RequestURI)
		}
		muxMutex.Unlock()
	}
}

// Get preferred outbound ip of this machine
func getOutboundIP() (ip net.IP, err error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

func mustGetOoutboundIP() net.IP {
	ip, err := getOutboundIP()
	if err != nil {
		return net.ParseIP("127.0.0.1")
		// panic(err)
	}
	return ip
}

func renderJSON(w http.ResponseWriter, data interface{}) {
	js, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(js)))
	w.Write(js)
}

func cmdError2Code(err error) int {
	if err == nil {
		return 0
	}
	if exiterr, ok := err.(*exec.ExitError); ok {
		// The program has exited with an exit code != 0

		// This works on both Unix and Windows. Although package
		// syscall is generally platform dependent, WaitStatus is
		// defined for both Unix and Windows and in both cases has
		// an ExitStatus() method with the same signature.
		if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	return 128
}

func GoFunc(f func() error) chan error {
	ch := make(chan error)
	go func() {
		ch <- f()
	}()
	return ch
}



var (
	deviceRotation        int
	displayMaxWidthHeight = 800
)


const (
	apkVersionCode = 5
	apkVersionName = "1.0.5"
)

func checkUiautomatorInstalled() (ok bool) {
	pi, err := androidutils.StatPackage("com.ftt.uiautomator")
	if err != nil {
		return
	}
	if pi.Version.Code < apkVersionCode {
		return
	}
	_, err = androidutils.StatPackage("com.ftt.uiautomator.test")
	return err == nil
}

func installAPK(path string) error {
	// -g: grant all runtime permissions
	// -d: allow version code downgrade
	// -r: replace existing application
	sdk, _ := strconv.Atoi(getCachedProperty("ro.build.version.sdk"))
	cmds := []string{"pm", "install", "-d", "-r", path}
	if sdk >= 23 { // android 6.0
		cmds = []string{"pm", "install", "-d", "-r", "-g", path}
	}
	out, err := runShell(cmds...)
	if err != nil {
		matches := regexp.MustCompile(`Failure \[([\w_ ]+)\]`).FindStringSubmatch(string(out))
		if len(matches) > 0 {
			return errors.Wrap(err, matches[0])
		}
		return errors.Wrap(err, string(out))
	}
	return nil
}

var canFixedInstallFails = map[string]bool{
	"INSTALL_FAILED_PERMISSION_MODEL_DOWNGRADE": true,
	"INSTALL_FAILED_UPDATE_INCOMPATIBLE":        true,
	"INSTALL_FAILED_VERSION_DOWNGRADE":          true,
}

func installAPKForce(path string, packageName string) error {
	err := installAPK(path)
	if err == nil {
		return nil
	}
	errType := regexp.MustCompile(`INSTALL_FAILED_[\w_]+`).FindString(err.Error())
	if !canFixedInstallFails[errType] {
		return err
	}
	runShell("pm", "uninstall", packageName)
	return installAPK(path)
}


type DownloadManager struct {
	db map[string]*downloadProxy
	mu sync.Mutex
	n  int
}

func newDownloadManager() *DownloadManager {
	return &DownloadManager{
		db: make(map[string]*downloadProxy, 10),
	}
}

func (m *DownloadManager) Get(id string) *downloadProxy {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.db[id]
}

func (m *DownloadManager) Put(di *downloadProxy) (id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n += 1
	id = strconv.Itoa(m.n)
	m.db[id] = di
	// di.Id = id
	return id
}

func (m *DownloadManager) Del(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.db, id)
}

func (m *DownloadManager) DelayDel(id string, sleep time.Duration) {
	go func() {
		time.Sleep(sleep)
		m.Del(id)
	}()
}

func AsyncDownloadTo(url string, filepath string, autoRelease bool) (di *downloadProxy, err error) {
	// do real http download
	res, err := goreq.Request{
		Uri:             url,
		MaxRedirects:    10,
		RedirectHeaders: true,
	}.Do()
	if err != nil {
		return
	}
	if res.StatusCode != http.StatusOK {
		body, err := res.Body.ToString()
		res.Body.Close()
		if err != nil && err != bytes.ErrTooLarge {
			return nil, fmt.Errorf("Expected HTTP Status code: %d", res.StatusCode)
		}
		return nil, errors.New(body)
	}
	file, err := os.Create(filepath)
	if err != nil {
		res.Body.Close()
		return
	}
	var totalSize int
	fmt.Sscanf(res.Header.Get("Content-Length"), "%d", &totalSize)
	di = newDownloadProxy(file, totalSize)
	downloadKey := downManager.Put(di)
	go func() {
		if autoRelease {
			defer downManager.Del(downloadKey)
		}
		defer di.Done()
		defer res.Body.Close()
		defer file.Close()
		io.Copy(di, res.Body)
	}()
	return
}

func currentUserName() string {
	if u, err := user.Current(); err == nil {
		return u.Name
	}
	if name := os.Getenv("USER"); name != "" {
		return name
	}
	output, err := exec.Command("whoami").Output()
	if err == nil {
		return strings.TrimSpace(string(output))
	}
	return ""
}

func renderHTML(w http.ResponseWriter, filename string) {
	file, err := Assets.Open(filename)
	if err != nil {
		http.Error(w, "404 page not found", 404)
		return
	}
	content, _ := ioutil.ReadAll(file)
	template.Must(template.New(filename).Parse(string(content))).Execute(w, nil)
}

var (
	ErrJpegWrongFormat = errors.New("jpeg format error, not starts with 0xff,0xd8")
)

type errorBinaryReader struct {
	rd  io.Reader
	err error
}

func (r *errorBinaryReader) ReadInto(datas ...interface{}) error {
	if r.err != nil {
		return r.err
	}
	for _, data := range datas {
		r.err = binary.Read(r.rd, binary.LittleEndian, data)
		if r.err != nil {
			return r.err
		}
	}
	return nil
}

// read from @minicap and send jpeg raw data to channel
func translateMinicap(conn net.Conn, jpgC chan []byte, quitC chan bool) error {
	var pid, rw, rh, vw, vh uint32
	var version, unused, orientation, quirkFlag uint8
	rd := bufio.NewReader(conn)
	binRd := errorBinaryReader{rd: rd}
	err := binRd.ReadInto(&version, &unused, &pid, &rw, &rh, &vw, &vh, &orientation, &quirkFlag)
	if err != nil {
		return err
	}
	for {
		var size uint32
		if err = binRd.ReadInto(&size); err != nil {
			break
		}

		lr := &io.LimitedReader{R: rd, N: int64(size)}
		buf := bytes.NewBuffer(nil)
		_, err = io.Copy(buf, lr)
		if err != nil {
			break
		}
		if string(buf.Bytes()[:2]) != "\xff\xd8" {
			err = ErrJpegWrongFormat
			break
		}
		select {
		case jpgC <- buf.Bytes(): // Maybe should use buffer instead
		case <-quitC:
			return nil
		default:
			// TODO(ssx): image should not wait or it will stuck here
		}
	}
	return err
}

func runDaemon() {
	environ := os.Environ()
	// env:IGNORE_SIGHUP forward stdout and stderr to file
	// env:ATX_AGENT will ignore -d flag
	environ = append(environ, "IGNORE_SIGHUP=true", "ATX_AGENT=1")
	cmd := kexec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = environ
	cmd.Start()
	select {
	case err := <-GoFunc(cmd.Wait):
		log.Fatalf("server started failed, %v", err)
	case <-time.After(200 * time.Millisecond):
		fmt.Printf("server started, listening on %v:%d\n", mustGetOoutboundIP(), listenPort)
	}
}

func main() {
	fDaemon := flag.Bool("d", false, "run daemon")
	flag.IntVar(&listenPort, "p", 7912, "listen port") // Create on 2017/09/12
	fSock5ProxyListenPort := flag.Int("sock5", 8719, "help message for flagname")  // Create on 2018/07/19
	fVersion := flag.Bool("v", false, "show version")
	fRequirements := flag.Bool("r", false, "install minicap and uiautomator.apk")
	fStop := flag.Bool("stop", false, "stop server")
	fTunnelServer := flag.String("t", "", "tunnel server address")
	fNoUiautomator := flag.Bool("nouia", false, "not start uiautomator")
	flag.Parse()

	if *fVersion {
		fmt.Println(version)
		return
	}

	defer func() {
		if e := recover(); e != nil {
			log.Println("Detect panic !!!", e)
			ioutil.WriteFile("/sdcard/atx-panic.txt", []byte(fmt.Sprintf(
				"Time: %s\n%v", time.Now().Format("2006-01-02 15:04:05"),
				e)), 0644)
		}
	}()

	if *fStop {
		_, err := http.Get("http://127.0.0.1:7912/stop")
		if err != nil {
			log.Println(err)
		} else {
			log.Println("server stopped")
		}
		return
	}

	if *fRequirements {
		log.Println("check dependencies")
		if err := installRequirements(); err != nil {
			// panic(err)
			log.Println("requirements not ready:", err)
			return
		}
	}

	os.Setenv("TMPDIR", "/sdcard/")
	if *fDaemon && os.Getenv("ATX_AGENT") == "" {
		runDaemon()
		return
	}

	if os.Getenv("IGNORE_SIGHUP") == "true" {
		fmt.Println("Enter into daemon mode")
		os.Unsetenv("IGNORE_SIGHUP")

		os.Rename("/sdcard/atx-agent.log", "/sdcard/atx-agent.log.old")
		f, err := os.Create("/sdcard/atx-agent.log")
		if err != nil {
			panic(err)
		}
		defer f.Close()

		os.Stdout = f
		os.Stderr = f
		os.Stdin = nil

		log.SetOutput(f)
		log.Println("Ignore SIGHUP")
		signal.Ignore(syscall.SIGHUP)

		// kill previous daemon first
		log.Println("Kill server")
		_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/stop", listenPort))
		if err == nil {
			log.Println("wait previous server stopped")
			time.Sleep(1000 * time.Millisecond) // server will quit in 0.1s
		} else {
			log.Println(err)
		}
	}

	fmt.Printf("atx-agent version %s\n", version)

	// show ip
	outIp, err := getOutboundIP()
	if err == nil {
		fmt.Printf("Listen on http://%v:%d\n", outIp, listenPort)
	} else {
		fmt.Printf("Internet is not connected.")
	}

	listener, err := net.Listen("tcp", ":"+ strconv.Itoa(listenPort))
	if err != nil {
		log.Fatal(err)
	}

	tunnel := &TunnelProxy{
		ServerAddr: *fTunnelServer,
		Secret:     "hello kitty",
	}
	if *fTunnelServer != "" {
		// go tunnel.RunForever()
		go tunnel.Heratbeat()
	}
	// run sock5 proxy at the background
	sock5 := Sock5Proxy{network:"tcp", address: fmt.Sprintf(":%d", *fSock5ProxyListenPort) }
	go sock5.startAgent()

	// run server forever
	ss := ServerHTTP{&listener, tunnel, mux.NewRouter()}
	if err := ss.start(fNoUiautomator); err != nil {
		log.Println("server quit:", err)
	}
}
