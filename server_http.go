package main

import (
	"net"
	"net/http"
	"io"
	"log"
	"encoding/base64"
	"strconv"
	"time"
	"io/ioutil"
	"strings"
	"encoding/json"
	"fmt"
	"sync"
	"context"
	"path"
	"path/filepath"
	"os"
	"os/signal"
	"os/exec"
	"runtime"
	"syscall"
	"net/http/httputil"
	"github.com/codeskyblue/procfs"
	"github.com/gorilla/websocket"
	"github.com/gorilla/mux"
	"github.com/openatx/androidutils"
	"github.com/shogo82148/androidbinary/apk"
	"github.com/openatx/atx-agent/cmdctrl"
	"github.com/rs/cors"
)


var uiautomatorProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "127.0.0.1:9008"
		},
		Transport: &http.Transport{
			// Ref: https://golang.org/pkg/net/http/#RoundTripper
			Dial: func(network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
					DualStack: true,
				}).Dial(network, addr)
				return conn, err
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       180 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
}

type MinicapInfo struct {
	Width    int     `json:"width"`
	Height   int     `json:"height"`
	Rotation int     `json:"rotation"`
	Density  float32 `json:"density"`
}

func updateMinicapRotation(rotation int) {
	devInfo := getDeviceInfo()
	width, height := devInfo.Display.Width, devInfo.Display.Height
	service.UpdateArgs("minicap", "/data/local/tmp/minicap", "-S", "-P",
		fmt.Sprintf("%dx%d@%dx%d/%d", width, height, displayMaxWidthHeight, displayMaxWidthHeight, rotation))
}

func Screenshot(filename string, thumbnailSize string) (err error) {
	output, err := runShellOutput("LD_LIBRARY_PATH=/data/local/tmp", "/data/local/tmp/minicap", "-i")
	if err != nil {
		return
	}
	var f MinicapInfo
	if er := json.Unmarshal([]byte(output), &f); er != nil {
		err = fmt.Errorf("minicap not supported: %v", er)
		return
	}
	if thumbnailSize == "" {
		thumbnailSize = fmt.Sprintf("%dx%d", f.Width, f.Height)
	}
	if _, err = runShell(
		"LD_LIBRARY_PATH=/data/local/tmp",
		"/data/local/tmp/minicap",
		"-P", fmt.Sprintf("%dx%d@%s/%d", f.Width, f.Height, thumbnailSize, f.Rotation),
		"-s", ">"+filename); err != nil {
		return
	}
	return nil
}



type ServerHTTP struct {
	lis	 		*net.Listener
	tunnel  	*TunnelProxy
	m 			*mux.Router
}


func (s *ServerHTTP) start (fNoUiautomator *bool) error {
	// 生成路由对象
	s.m = mux.NewRouter()

	// 注册server运行需要的命令
	// minicap + minitouch
	devInfo := getDeviceInfo()
	width, height := devInfo.Display.Width, devInfo.Display.Height
	service.Add("minicap", cmdctrl.CommandInfo{
		Environ: []string{"LD_LIBRARY_PATH=/data/local/tmp"},
		Args: []string{"/data/local/tmp/minicap", "-S", "-P",
			fmt.Sprintf("%dx%d@%dx%d/0", width, height, displayMaxWidthHeight, displayMaxWidthHeight)},
	})
	service.Add("minitouch", cmdctrl.CommandInfo{
		Args: []string{"/data/local/tmp/minitouch"},
	})

	// uiautomator
	service.Add("uiautomator", cmdctrl.CommandInfo{
		Args: []string{"am", "instrument", "-w", "-r",
			"-e", "debug", "false",
			"-e", "class", "com.ftt.uiautomator.stub.Stub",
			"com.qiyi.ftt.test/android.support.test.runner.AndroidJUnitRunner"},
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		MaxRetries:      3,
		RecoverDuration: 30 * time.Second,
	})

	if !*fNoUiautomator {
		if _, err := runShell("am", "start", "-W", "-n", "com.qiyi.ftt/.MainActivity"); err != nil {
			log.Println("start uiautomator err:", err)
		}
		if err := service.Start("uiautomator"); err != nil {
			log.Println("uiautomator start failed:", err)
		}
	}


	s.m.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		renderHTML(writer, "index.html")
	})

	s.m.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, version)
	})

	s.m.HandleFunc("/remote", func(w http.ResponseWriter, r *http.Request) {
		renderHTML(w, "remote.html")
	})

	s.m.HandleFunc("/raw/{filepath:.*}", func(w http.ResponseWriter, r *http.Request) {
		filepath := mux.Vars(r)["filepath"]
		http.ServeFile(w, r, filepath)
	})

	s.m.HandleFunc("/term", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			handleTerminalWebsocket(w, r)
			return
		}
		renderHTML(w, "terminal.html")
	})

	// 添加url处理的方法
	s.whatsinput()
	s.pkgname()
	s.shell()
	s.uiautomator()
	s.keepRunning()
	s.transfer()
	s.install()
	s.minitouch()
	s.minicap()
	s.screenrecord()
	s.upgrade()

	// 注册中断信号处理
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for sig := range sigc {
			log.Println("receive signal", sig)
			service.StopAll()
			os.Exit(0)
			httpServer.Shutdown(context.TODO())
		}
	}()

	//
	var handler = cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE"},
	}).Handler(s.m)
	httpServer = &http.Server{Handler: handler} // url(/stop) need it.
	return httpServer.Serve(*s.lis)
}


// simple pubsub system
func (s *ServerHTTP) whatsinput(){
	/* WhatsInput */
	var whatsinput = struct {
		ChangeC  chan string
		EditC    chan string
		KeyCodeC chan int
		Recent   string
	}{make(chan string, 0), make(chan string, 0), make(chan int, 0), ""}

	const whatsInputFinishedMagic = "__inputFinished__"

	// simple pubsub system
	s.m.HandleFunc("/whatsinput", func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("Host")
		log.Println("CONNECT", host)
		conn, err := hijackHTTPRequest(w)
		if err != nil {
			log.Println("Hijack failed:", err)
			return
		}
		quit := make(chan bool, 1)
		go func() {
			for {
				select {
				case text := <-whatsinput.EditC:
					base64Str := base64.StdEncoding.EncodeToString([]byte(text)) + "\n"
					conn.Write([]byte("I" + base64Str))
				case keyCode := <-whatsinput.KeyCodeC:
					conn.Write([]byte("K" + strconv.Itoa(keyCode)))
				case <-time.After(10 * time.Second):
					conn.Write([]byte("P")) // ping message
				case <-quit:
					return
				}
			}
		}()

		buf := make([]byte, 4096)
		for {
			_, err := conn.Read(buf)
			if err != nil {
				quit <- true
				break
			}
		}
	}).Methods("CONNECT")

	// Send input to device
	// Highly affected by project https://github.com/willerce/WhatsInput
	// Also thanks to https://github.com/senzhk/ADBKeyBoard
	s.m.HandleFunc("/whatsinput", singleFightNewerWebsocket(func(w http.ResponseWriter, r *http.Request, ws *websocket.Conn) {
		var v struct {
			Type string `json:"type"`
			Text string `json:"text,omitempty"`
			Code int    `json:"code,omitempty"`
		}
		quit := make(chan bool, 1)
		go func() {
			for {
				select {
				case msg := <-whatsinput.ChangeC:
					log.Println("Receive msg", msg)
					if msg == whatsInputFinishedMagic {
						log.Println("FinishedInput")
						ws.WriteJSON(map[string]string{
							"type": "InputFinish",
						})
					} else {
						ws.WriteJSON(map[string]string{
							"type": "InputStart",
							"text": msg,
						})
					}
				case <-quit:
					return
				}
			}
		}()
		for {
			if err := ws.ReadJSON(&v); err != nil {
				quit <- true
				log.Println(err)
				break
			}
			switch v.Type {
			case "InputEdit":
				select {
				case whatsinput.EditC <- v.Text:
					log.Println("Message sended", v.Text)
				case <-time.After(100 * time.Millisecond):
				}
				// runShell("am", "broadcast", "-a", "ADB_SET_TEXT", "--es", "text", strconv.Quote(base64Str))
			case "InputKey":
				runShell("input", "keyevent", "KEYCODE_ENTER") // HOTFIX(ssx): need fix later
				// runShell("am", "broadcast", "-a", "ADB_INPUT_KEYCODE", "--ei", "code", strconv.Itoa(v.Code))
			}
		}
	})).Methods("GET")

	s.m.HandleFunc("/whatsinput", func(w http.ResponseWriter, r *http.Request) {
		data, _ := ioutil.ReadAll(r.Body)
		if string(data) == "" {
			http.Error(w, "Empty body", http.StatusForbidden)
			return
		}
		var input string
		if data[0] == 'I' {
			input = string(data[1:])
			whatsinput.Recent = input
		} else {
			input = whatsInputFinishedMagic
			whatsinput.Recent = ""
		}
		select {
		case whatsinput.ChangeC <- input:
			io.WriteString(w, "Success")
		case <-time.After(100 * time.Millisecond):
			io.WriteString(w, "No WebSocket client connected")
		}
	}).Methods("POST")
}


func (s *ServerHTTP) pkgname(){
	s.m.HandleFunc("/pidof/{pkgname}", func(w http.ResponseWriter, r *http.Request) {
		pkgname := mux.Vars(r)["pkgname"]
		if pid, err := pidOf(pkgname); err == nil {
			io.WriteString(w, strconv.Itoa(pid))
			return
		}
	})

	s.m.HandleFunc("/session/{pkgname}", func(w http.ResponseWriter, r *http.Request) {
		packageName := mux.Vars(r)["pkgname"]
		mainActivity, err := mainActivityOf(packageName)
		if err != nil {
			http.Error(w, err.Error(), http.StatusGone) // 410
			return
		}
		// Refs: https://stackoverflow.com/questions/12131555/leading-dot-in-androidname-really-required
		// MainActivity convert to .MainActivity
		// com.example.app.MainActivity keep same
		// app.MainActivity keep same
		// So only words not contains dot, need to add prefix "."
		if !strings.Contains(mainActivity, ".") {
			mainActivity = "." + mainActivity
		}

		flags := r.FormValue("flags")
		if flags == "" {
			flags = "-W -S" // W: wait launched, S: stop before started
		}

		w.Header().Set("Content-Type", "application/json")
		output, err := runShellTimeout(10*time.Second, "am", "start", flags, "-n", packageName+"/"+mainActivity)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":      false,
				"error":        err.Error(),
				"output":       string(output),
				"mainActivity": mainActivity,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success":      true,
				"mainActivity": mainActivity,
				"output":       string(output),
			})
		}
	}).Methods("POST")


	s.m.HandleFunc("/session/{pid:[0-9]+}:{pkgname}/{url:ping|jsonrpc/0}", func(w http.ResponseWriter, r *http.Request) {
		pkgname := mux.Vars(r)["pkgname"]
		pid, _ := strconv.Atoi(mux.Vars(r)["pid"])

		pfs, err := procfs.NewFS(procfs.DefaultMountPoint)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		proc, err := pfs.NewProc(pid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusGone) // 410
			return
		}
		cmdline, _ := proc.CmdLine()
		if len(cmdline) != 1 || cmdline[0] != pkgname {
			http.Error(w, fmt.Sprintf("cmdline expect [%s] but got %v", pkgname, cmdline), http.StatusGone)
			return
		}
		r.URL.Path = "/" + mux.Vars(r)["url"]
		uiautomatorProxy.ServeHTTP(w, r)
	})
}

func (s *ServerHTTP) shell()  {
	s.m.HandleFunc("/shell", func(w http.ResponseWriter, r *http.Request) {
		command := r.FormValue("command")
		if command == "" {
			command = r.FormValue("c")
		}
		timeoutSeconds := r.FormValue("timeout")
		if timeoutSeconds == "" {
			timeoutSeconds = "60"
		}
		seconds, err := strconv.Atoi(timeoutSeconds)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		c := Command{
			Args:    []string{command},
			Shell:   true,
			Timeout: time.Duration(seconds) * time.Second,
		}
		output, err := c.CombinedOutput()
		exitCode := cmdError2Code(err)
		renderJSON(w, map[string]interface{}{
			"output":   string(output),
			"exitCode": exitCode,
			"error":    err,
		})
	}).Methods("GET", "POST")

	s.m.HandleFunc("/shell/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		command := r.FormValue("command")
		if command == "" {
			command = r.FormValue("c")
		}
		c := exec.Command("sh", "-c", command)

		httpWriter := newFakeWriter(func(data []byte) (int, error) {
			n, err := w.Write(data)
			if err == nil {
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			} else {
				log.Println("Write error")
			}
			return n, err
		})
		c.Stdout = httpWriter
		c.Stderr = httpWriter

		// wait until program quit
		cmdQuit := make(chan error, 0)
		go func() {
			cmdQuit <- c.Run()
		}()
		select {
		case <-httpWriter.Err:
			if c.Process != nil {
				c.Process.Signal(syscall.SIGTERM)
			}
		case <-cmdQuit:
			log.Println("command quit")
		}
		log.Println("program quit")
	})
}


func (s *ServerHTTP) uiautomator()  {
	s.m.HandleFunc("/stop", func(w http.ResponseWriter, r *http.Request) {
		log.Println("stop all service")
		service.StopAll()
		log.Println("service stopped")
		io.WriteString(w, "Finished!")
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel() // The document says need to call cancel(), but I donot known why.
			httpServer.Shutdown(ctx)
		}()
	})

	s.m.HandleFunc("/uiautomator", func(w http.ResponseWriter, r *http.Request) {
		err := service.Start("uiautomator")
		if err == nil {
			io.WriteString(w, "Success")
		} else {
			http.Error(w, err.Error(), 500)
		}
	}).Methods("POST")

	s.m.HandleFunc("/uiautomator", func(w http.ResponseWriter, r *http.Request) {
		err := service.Stop("uiautomator", true) // wait until program quit
		if err == nil {
			io.WriteString(w, "Success")
		} else {
			http.Error(w, err.Error(), 500)
		}
	}).Methods("DELETE")


	screenshotIndex := -1
	nextScreenshotFilename := func() string {
		targetFolder := "/data/local/tmp/minicap-images"
		if _, err := os.Stat(targetFolder); err != nil {
			os.MkdirAll(targetFolder, 0755)
		}
		screenshotIndex = (screenshotIndex + 1) % 5
		return filepath.Join(targetFolder, fmt.Sprintf("%d.jpg", screenshotIndex))
	}

	s.m.HandleFunc("/screenshot", func(w http.ResponseWriter, r *http.Request) {
		targetURL := "/screenshot/0"
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, targetURL, 302)
	}).Methods("GET")

	s.m.Handle("/jsonrpc/0", uiautomatorProxy)
	s.m.Handle("/ping", uiautomatorProxy)
	s.m.HandleFunc("/screenshot/0", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("minicap") == "false" || strings.ToLower(getCachedProperty("ro.product.manufacturer")) == "meizu" {
			uiautomatorProxy.ServeHTTP(w, r)
			return
		}
		thumbnailSize := r.FormValue("thumbnail")
		filename := nextScreenshotFilename()
		if err := Screenshot(filename, thumbnailSize); err != nil {
			log.Printf("screenshot[minicap] error: %v", err)
			uiautomatorProxy.ServeHTTP(w, r)
		} else {
			w.Header().Set("X-Screenshot-Method", "minicap")
			http.ServeFile(w, r, filename)
		}
	})

	s.m.Handle("/assets/{(.*)}", http.StripPrefix("/assets", http.FileServer(Assets)))
}

func (s *ServerHTTP) keepRunning(){
	runShell("am", "startservice", "-n", "com.qiyi.ftt/.Service")
	// keep ApkService always running
	// if no activity in 3min, then restart apk service
	const apkServiceTimeout = 3 * time.Minute
	apkServiceTimer := time.NewTimer(apkServiceTimeout)
	go func() {
		for range apkServiceTimer.C {
			log.Println("startservice com.qiyi.ftt/.Service")
			// TODO
			runShell("am", "startservice", "-n", "com.qiyi.ftt/.Service")
			apkServiceTimer.Reset(apkServiceTimeout)
		}
	}()

	s.m.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		info := getDeviceInfo()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	})


	s.m.HandleFunc("/info/battery", func(w http.ResponseWriter, r *http.Request) {
		apkServiceTimer.Reset(apkServiceTimeout)
		devInfo := getDeviceInfo()
		devInfo.Battery.Update()
		if err := s.tunnel.UpdateInfo(devInfo); err != nil {
			io.WriteString(w, "Failure "+err.Error())
			return
		}
		io.WriteString(w, "Success")
	}).Methods("POST")

	s.m.HandleFunc("/info/rotation", func(w http.ResponseWriter, r *http.Request) {
		apkServiceTimer.Reset(apkServiceTimeout)
		var direction int                                 // 0,1,2,3
		err := json.NewDecoder(r.Body).Decode(&direction) // TODO: auto get rotation
		if err == nil {
			deviceRotation = direction * 90
			log.Println("rotation change received:", deviceRotation)
		} else {
			rotation, er := androidutils.Rotation()
			if er != nil {
				log.Println("rotation auto get err:", er)
				http.Error(w, "Failure", 500)
				return
			}
			deviceRotation = rotation
		}
		updateMinicapRotation(deviceRotation)
		// APK Service will send rotation to atx-agent when rotation changes
		runShellTimeout(5*time.Second, "am", "startservice", "--user", "0", "-n", "com.qiyi.ftt/.Service")
		fmt.Fprintf(w, "rotation change to %d", deviceRotation)
	})
}


func (s *ServerHTTP) transfer(){

	s.m.HandleFunc("/upload/{target:.*}", func(w http.ResponseWriter, r *http.Request) {
		target := mux.Vars(r)["target"]
		if runtime.GOOS != "windows" {
			target = "/" + target
		}
		var fileMode os.FileMode
		if _, err := fmt.Sscanf(r.FormValue("mode"), "%o", &fileMode); err != nil {
			log.Printf("invalid file mode: %s", r.FormValue("mode"))
			fileMode = 0644
		} // %o base 8

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		defer func() {
			file.Close()
			r.MultipartForm.RemoveAll()
		}()
		if strings.HasSuffix(target, "/") {
			target = path.Join(target, header.Filename)
		}

		targetDir := filepath.Dir(target)
		if _, err := os.Stat(targetDir); os.IsNotExist(err) {
			os.MkdirAll(targetDir, 0755)
		}

		fd, err := os.Create(target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer fd.Close()
		written, err := io.Copy(fd, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if fileMode != 0 {
			os.Chmod(target, fileMode)
		}
		if fileInfo, err := os.Stat(target); err == nil {
			fileMode = fileInfo.Mode()
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"target": target,
			"size":   written,
			"mode":   fmt.Sprintf("0%o", fileMode),
		})
	})

	s.m.HandleFunc("/download", func(w http.ResponseWriter, r *http.Request) {
		dst := r.FormValue("filepath")
		url := r.FormValue("url")
		var fileMode os.FileMode
		if _, err := fmt.Sscanf(r.FormValue("mode"), "%o", &fileMode); err != nil {
			log.Printf("invalid file mode: %s", r.FormValue("mode"))
			fileMode = 0644
		} // %o base 8
		key := background.HTTPDownload(url, dst, fileMode)
		io.WriteString(w, key)
	}).Methods("POST")

	s.m.HandleFunc("/download/{key}", func(w http.ResponseWriter, r *http.Request) {
		key := mux.Vars(r)["key"]
		status := background.Get(key)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}).Methods("GET")

}


func (s *ServerHTTP) install() {
	s.m.HandleFunc("/install", func(w http.ResponseWriter, r *http.Request) {
		var url = r.FormValue("url")
		filepath := TempFileName("/sdcard/tmp", ".apk")
		key := background.HTTPDownload(url, filepath, 0644)
		go func() {
			defer os.Remove(filepath) // release sdcard space

			state := background.Get(key)
			if err := background.Wait(key); err != nil {
				log.Println("http download error")
				state.Error = err.Error()
				state.Message = "http download error"
				return
			}

			state.Message = "apk parsing"
			pkg, er := apk.OpenFile(filepath)
			if er != nil {
				state.Error = er.Error()
				state.Message = "androidbinary parse apk error"
				return
			}
			defer pkg.Close()
			packageName := pkg.PackageName()
			state.PackageName = packageName

			state.Message = "installing"
			if err := installAPKForce(filepath, packageName); err != nil {
				state.Error = err.Error()
				state.Message = "error install"
			} else {
				state.Message = "success installed"
			}
		}()
		io.WriteString(w, key)
	}).Methods("POST")

	s.m.HandleFunc("/install/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		state := background.Get(id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(state)
	}).Methods("GET")

	s.m.HandleFunc("/install/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		state := background.Get(id)
		if state.Progress != nil {
			if dproxy, ok := state.Progress.(*downloadProxy); ok {
				dproxy.Cancel()
				io.WriteString(w, "Cancelled")
				return
			}
		}
		io.WriteString(w, "Unable to canceled")
	}).Methods("DELETE")
}


func (s *ServerHTTP) minitouch(){
	// fix minitouch
	s.m.HandleFunc("/minitouch", func(w http.ResponseWriter, r *http.Request) {
		if err := installMinitouch(); err == nil {
			log.Println("update minitouch success")
			io.WriteString(w, "Update minitouch success")
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("PUT")

	s.m.HandleFunc("/minitouch", singleFightNewerWebsocket(func(w http.ResponseWriter, r *http.Request, ws *websocket.Conn) {
		defer ws.Close()
		const wsWriteWait = 10 * time.Second
		wsWrite := func(messageType int, data []byte) error {
			ws.SetWriteDeadline(time.Now().Add(wsWriteWait))
			return ws.WriteMessage(messageType, data)
		}
		wsWrite(websocket.TextMessage, []byte("start @minitouch service"))
		if err := service.Start("minitouch"); err != nil && err != cmdctrl.ErrAlreadyRunning {
			wsWrite(websocket.TextMessage, []byte("@minitouch service start failed: "+err.Error()))
			return
		}
		wsWrite(websocket.TextMessage, []byte("dial unix:@minitouch"))
		log.Printf("minitouch connection: %v", r.RemoteAddr)
		retries := 0
		quitC := make(chan bool, 2)
		operC := make(chan TouchRequest, 10)
		defer func() {
			wsWrite(websocket.TextMessage, []byte("unix:@minitouch websocket closed"))
			close(operC)
		}()
		go func() {
			for {
				if retries > 10 {
					log.Println("unix @minitouch connect failed")
					wsWrite(websocket.TextMessage, []byte("@minitouch listen timeout, possibly minitouch not installed"))
					ws.Close()
					break
				}
				conn, err := net.Dial("unix", "@minitouch")
				if err != nil {
					retries++
					log.Printf("dial @minitouch error: %v, wait 0.5s", err)
					select {
					case <-quitC:
						return
					case <-time.After(500 * time.Millisecond):
					}
					continue
				}
				log.Println("unix @minitouch connected, accepting requests")
				retries = 0 // connected, reset retries
				err = drainTouchRequests(conn, operC)
				conn.Close()
				if err != nil {
					log.Println("drain touch requests err:", err)
				} else {
					log.Println("unix @minitouch disconnected")
					break // operC closed
				}
			}
		}()
		var touchRequest TouchRequest
		for {
			err := ws.ReadJSON(&touchRequest)
			if err != nil {
				log.Println("readJson err:", err)
				quitC <- true
				break
			}
			select {
			case operC <- touchRequest:
			case <-time.After(2 * time.Second):
				wsWrite(websocket.TextMessage, []byte("touch request buffer full"))
			}
		}
	})).Methods("GET")
}

func (s *ServerHTTP) minicap(){
	// fix minicap
	s.m.HandleFunc("/minicap", func(w http.ResponseWriter, r *http.Request) {
		if err := installMinicap(); err == nil {
			log.Println("update minicap success")
			io.WriteString(w, "Update minicap success")
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}).Methods("PUT")

	s.m.HandleFunc("/minicap", singleFightNewerWebsocket(func(w http.ResponseWriter, r *http.Request, ws *websocket.Conn) {
		defer ws.Close()

		const wsWriteWait = 10 * time.Second
		wsWrite := func(messageType int, data []byte) error {
			ws.SetWriteDeadline(time.Now().Add(wsWriteWait))
			return ws.WriteMessage(messageType, data)
		}
		wsWrite(websocket.TextMessage, []byte("restart @minicap service"))
		if err := service.Restart("minicap"); err != nil && err != cmdctrl.ErrAlreadyRunning {
			wsWrite(websocket.TextMessage, []byte("@minicap service start failed: "+err.Error()))
			return
		}

		wsWrite(websocket.TextMessage, []byte("dial unix:@minicap"))
		log.Printf("minicap connection: %v", r.RemoteAddr)
		dataC := make(chan []byte, 10)
		quitC := make(chan bool, 2)

		go func() {
			defer close(dataC)
			retries := 0
			for {
				if retries > 10 {
					log.Println("unix @minicap connect failed")
					dataC <- []byte("@minicap listen timeout, possibly minicap not installed")
					break
				}
				conn, err := net.Dial("unix", "@minicap")
				if err != nil {
					retries++
					log.Printf("dial @minicap err: %v, wait 0.5s", err)
					select {
					case <-quitC:
						return
					case <-time.After(500 * time.Millisecond):
					}
					continue
				}
				dataC <- []byte("rotation " + strconv.Itoa(deviceRotation))
				retries = 0 // connected, reset retries
				if er := translateMinicap(conn, dataC, quitC); er == nil {
					conn.Close()
					log.Println("transfer closed")
					break
				} else {
					conn.Close()
					log.Println("minicap read error, try to read again")
				}
			}
		}()
		go func() {
			for {
				if _, _, err := ws.ReadMessage(); err != nil {
					quitC <- true
					break
				}
			}
		}()
		for data := range dataC {
			if string(data[:2]) == "\xff\xd8" { // jpeg data
				if err := wsWrite(websocket.BinaryMessage, data); err != nil {
					break
				}
				if err := wsWrite(websocket.TextMessage, []byte("data size: "+strconv.Itoa(len(data)))); err != nil {
					break
				}
			} else {
				if err := wsWrite(websocket.TextMessage, data); err != nil {
					break
				}
			}
		}
		quitC <- true
		log.Println("stream finished")
	})).Methods("GET")
}

func (s *ServerHTTP) screenrecord() {
	// TODO(ssx): perfer to delete
	// FIXME(ssx): screenrecord is not good enough, need to change later
	var recordCmd *exec.Cmd
	var recordDone = make(chan bool, 1)
	var recordLock sync.Mutex
	var recordFolder = "/sdcard/screenrecords/"
	var recordRunning = false


	s.m.HandleFunc("/screenrecord", func(w http.ResponseWriter, r *http.Request) {
		recordLock.Lock()
		defer recordLock.Unlock()

		if recordCmd != nil {
			http.Error(w, "screenrecord not closed", 400)
			return
		}
		os.RemoveAll(recordFolder)
		os.MkdirAll(recordFolder, 0755)
		recordCmd = exec.Command("screenrecord", recordFolder+"0.mp4")
		if err := recordCmd.Start(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		recordRunning = true
		go func() {
			for i := 1; recordCmd.Wait() == nil && i <= 20 && recordRunning; i++ { // set limit, to prevent too many videos. max 1 hour
				recordCmd = exec.Command("screenrecord", recordFolder+strconv.Itoa(i)+".mp4")
				if err := recordCmd.Start(); err != nil {
					log.Println("screenrecord error:", err)
					break
				}
			}
			recordDone <- true
		}()
		io.WriteString(w, "screenrecord started")
	}).Methods("POST")


	s.m.HandleFunc("/screenrecord", func(w http.ResponseWriter, r *http.Request) {
		recordLock.Lock()
		defer recordLock.Unlock()

		recordRunning = false
		if recordCmd != nil {
			if recordCmd.Process != nil {
				recordCmd.Process.Signal(os.Interrupt)
			}
			select {
			case <-recordDone:
			case <-time.After(5 * time.Second):
				// force kill
				exec.Command("pkill", "screenrecord").Run()
			}
			recordCmd = nil
		}
		w.Header().Set("Content-Type", "application/json")
		files, _ := ioutil.ReadDir(recordFolder)
		videos := []string{}
		for i := 0; i < len(files); i++ {
			videos = append(videos, fmt.Sprintf(recordFolder+"%d.mp4", i))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"videos": videos,
		})
	}).Methods("PUT")
}

func (s *ServerHTTP)  upgrade() {
	s.m.HandleFunc("/upgrade", func(w http.ResponseWriter, r *http.Request) {
		ver := r.FormValue("version")
		var err error
		if ver == "" {
			ver, err = getLatestVersion()
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		if ver == version {
			io.WriteString(w, "current version is already "+version)
			return
		}
		err = doUpdate(ver)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		io.WriteString(w, "update finished, restarting")
		go func() {
			log.Printf("restarting server")
			runDaemon()
		}()
	})
}