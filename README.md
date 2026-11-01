<div align="center">

<pre>
                    ,
               ,.  | \
              |: \ ; :\
              :' ;\| ::\
               \ : | `::\
               _)  |   `:.
             ,' , `.    ;: ;
           ,' ;:  ;"'  ,:: |_
          /,   ` .    ;::: |:`-.__
       _,' _o\  ,::.`:' ;  ;   . '
   _,-'           `:.          ;""\,
,-'                     ,:         `-;,
\,                       ;:           ;--._
 `.______,-,----._     ,' ;:        ,/ ,  ,`
        / /,-';'  \     ; `:      ,'/,::.:::
      ,',;-'-'_,--;    ;   :.   ,',',;::::::
     ( /___,-'     `.     ;::,,'o/  ,:::::::
      `'             )    ;:,'o /  ;"-   -::
                     \__ _,'o ,'         ,::
                        ) `--'       ,..::::
     -ByteHound-        ; `.        ,:::::::
                         ;  `::.    :::::::
</pre>

<h1>ByteHound</h1>

<p><strong>A lightweight file byte scanner.</strong></p>

<p>
  <strong>Version:</strong> 0.1<br>
  <strong>Author:</strong> Muh. Agus Tri Ananda<br>
  <strong>GitHub:</strong> BangAguse
</p>

<p>
  <a href="#features">Features</a> ·
  <a href="#installation">Installation</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#android-usb-scan">Android over USB</a> ·
  <a href="#reports">Reports</a> ·
  <a href="#limitations">Limitations</a>
</p>

</div>

<hr>

<h2 id="features">Features</h2>

<ul>
  <li>Recursively scans regular files in a local directory, using a concurrent Go worker pool and a Rust scanning library.</li>
  <li>Uses read-only memory mapping and an Aho–Corasick automaton for the bundled byte-pattern signatures.</li>
  <li>Reports Shannon entropy as a heuristic signal; it is not a malware verdict.</li>
  <li>Includes <code>--fast</code> mode for a limited set of executable and script extensions.</li>
  <li>Can scan accessible Android shared storage over USB through Android Debug Bridge (ADB).</li>
  <li>Exports reports as TXT, JSON, CSV, or PDF.</li>
</ul>

<h2 id="requirements">Requirements</h2>

<table>
  <thead>
    <tr><th>Platform</th><th>Requirements</th></tr>
  </thead>
  <tbody>
    <tr>
      <td>Linux</td>
      <td>Go 1.22+, Rust/Cargo, Make, a C compiler, and cgo enabled.</td>
    </tr>
    <tr>
      <td>macOS</td>
      <td>Go 1.22+, Rust/Cargo, Make, Xcode Command Line Tools, and cgo enabled.</td>
    </tr>
    <tr>
      <td>Windows</td>
      <td>Go 1.22+, Rust/Cargo with the MSVC toolchain, and PowerShell.</td>
    </tr>
  </tbody>
</table>

<p>Android device scanning also requires Android Platform Tools (<code>adb</code>), a data-capable USB cable, and USB debugging authorization on the phone.</p>

<h2 id="installation">Installation</h2>

<h3>Linux and macOS</h3>

<p>Clone or download the project, open a terminal in the project directory, and run:</p>

<pre><code>./install.sh</code></pre>

<p>The script builds the Rust library and Go CLI. It installs both in <code>/usr/local/bin</code> when it can write there; otherwise it uses <code>~/.local/bin</code>. If that directory is not already on your <code>PATH</code>, add it to your shell configuration.</p>

<p>To build without installing globally:</p>

<pre><code>make build
./bin/bytehound --help</code></pre>

<h3>Windows</h3>

<p>Run PowerShell from the project directory:</p>

<pre><code>.\install.ps1</code></pre>

<p>The script builds the Rust DLL and Go executable, installs them under <code>%LOCALAPPDATA%\ByteHound\bin</code>, and adds that directory to your user <code>PATH</code>. Open a new terminal after installation.</p>

<h3>Build and test</h3>

<pre><code>make build
make test</code></pre>

<p>The build output is placed in <code>bin/</code>. The executable needs its matching Rust shared library beside it. To select a library at a custom location, set <code>BYTEHOUND_SCANNER_LIB</code>.</p>

<h2 id="usage">Usage</h2>

<pre><code>bytehound --help
bytehound
bytehound --path ./evidence --verbose
bytehound --path ./evidence --fast --output report.json</code></pre>

<table>
  <thead>
    <tr><th>Option</th><th>Description</th></tr>
  </thead>
  <tbody>
    <tr><td><code>-h</code>, <code>--help</code></td><td>Show the usage guide.</td></tr>
    <tr><td><code>-v</code>, <code>--verbose</code></td><td>Print each file as it is scanned.</td></tr>
    <tr><td><code>--path &lt;directory&gt;</code></td><td>Scan this local directory. Defaults to the current directory.</td></tr>
    <tr><td><code>-o</code>, <code>--output &lt;file&gt;</code></td><td>Write a report. The file extension selects the format.</td></tr>
    <tr><td><code>--fast</code></td><td>Scan selected executable and script extensions; other files are skipped.</td></tr>
    <tr><td><code>--device</code></td><td>Scan accessible Android shared storage over USB using ADB.</td></tr>
    <tr><td><code>--device-serial &lt;serial&gt;</code></td><td>Select a connected Android device when more than one is authorized.</td></tr>
  </tbody>
</table>

<p><code>--path</code> and <code>--device</code> are mutually exclusive. In local mode, ByteHound scans regular files recursively and does not follow symlinks. In fast mode, the scanner only selects configured extensions such as <code>.exe</code>, <code>.sh</code>, <code>.py</code>, <code>.php</code>, <code>.js</code>, and <code>.bin</code>; other files are skipped.</p>

<h2 id="android-usb-scan">Android over USB</h2>

<ol>
  <li>Install Android Platform Tools on the laptop so <code>adb</code> is available in the terminal.</li>
  <li>On the phone, enable <strong>Developer options</strong>, then turn on <strong>USB debugging</strong>.</li>
  <li>Connect the phone with a data-capable USB cable and unlock its screen.</li>
  <li>When prompted, allow USB debugging for this computer.</li>
  <li>From the laptop, check that ADB sees the phone:
    <pre><code>adb devices</code></pre>
  </li>
  <li>Start the scan:
    <pre><code>bytehound --device</code></pre>
  </li>
</ol>

<p>If more than one authorized phone is connected, choose one using its serial from <code>adb devices</code>:</p>

<pre><code>bytehound --device --device-serial &lt;serial&gt; --output phone-report.json</code></pre>

<p>Device mode reads files under Android shared storage (<code>/sdcard</code>), such as accessible downloads, photos, and documents. It transfers one file at a time to a temporary directory on the laptop for scanning and removes temporary file copies when finished. Save a report with <code>--output</code> if you want to keep the results.</p>

<p><strong>Android access boundary:</strong> a USB connection does not grant access to the whole phone. On a standard, non-rooted Android device, private app data and protected system files are not accessible to ordinary ADB shell access. ByteHound does not bypass Android permissions or root the device.</p>

<h2 id="reports">Reports</h2>

<p>Supported extensions are <code>.txt</code>, <code>.json</code>, <code>.csv</code>, and <code>.pdf</code>. ByteHound chooses the report format from the output filename:</p>

<pre><code>bytehound --path ./evidence --output scan-report.json
bytehound --device --output phone-report.csv</code></pre>

<h2 id="interface">Terminal interface</h2>

<p>The CLI uses a restrained teal accent and a progress indicator. ANSI colors are used only when output is sent to a terminal. Set <code>NO_COLOR</code> to disable colors.</p>

<h2 id="limitations">Detection and safety notes</h2>

<ul>
  <li>The built-in Aho–Corasick patterns are a small illustrative set, not a maintained malware signature database. They include the EICAR test marker.</li>
  <li>High entropy is common in compressed, encrypted, and media files. It is only a heuristic and cannot reliably identify malware or zero-day threats.</li>
  <li>A match or entropy alert is an indicator for review, not a confirmed infection. False positives and missed detections are possible.</li>
  <li>Scanning is read-only: ByteHound does not quarantine, delete, or execute files.</li>
  <li>Linux and macOS scan files through read-only memory mapping. Avoid modifying or truncating files while a scan is in progress.</li>
  <li>Only scan devices and files you own or are authorized to examine.</li>
</ul>

<h2 id="project-layout">Project layout</h2>

<pre><code>ByteHound/
├── main.go
├── scan.go
├── device.go
├── scanner_native.go
├── scanner_native_unix.go
├── scanner_native_windows.go
├── report.go
├── report_pdf.go
├── ui.go
├── go.mod
├── Makefile
├── install.sh
├── install.ps1
└── scanner/
    ├── Cargo.toml
    └── src/lib.rs</code></pre>

<hr>

<p align="center"><sub>ByteHound 0.1 · Author: Muh. Agus Tri Ananda · GitHub: BangAguse</sub></p>
