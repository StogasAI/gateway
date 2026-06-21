(define-module (release)
  #:use-module (gnu packages)
  #:use-module (guix build-system trivial)
  #:use-module (guix gexp)
  #:use-module (guix packages)
  #:use-module (ice-9 match)
  #:use-module (ice-9 textual-ports)
  #:use-module (stogas release packages))

(define %this-file
  (or (current-filename)
      (and=> (getenv "STOGAS_RELEASE_ROOT")
             (lambda (root) (string-append root "/guix/release.scm")))))

(define %guix-dir
  (dirname %this-file))

(define %release-root
  (dirname %guix-dir))

(define %gateway-root
  (dirname (dirname %release-root)))

(define %release-tag
  (or (getenv "STOGAS_RELEASE_TAG") "v0.0.0"))

(define %release-commit
  (or (getenv "STOGAS_RELEASE_COMMIT")
      "0000000000000000000000000000000000000000"))

(define %release-tree
  (or (getenv "STOGAS_RELEASE_TREE")
      "0000000000000000000000000000000000000000"))

(define (release-sequence tag)
  (let* ((version (substring tag 1))
         (parts (map string->number (string-split version #\.))))
    (match parts
      ((major minor patch)
       (+ (* major 1000000000000) (* minor 1000000) patch))
      (_ 0))))

(define (runtime-source-path? file)
  (or (string=? file "core")
      (string-prefix? "core/" file)
      (string=? file "transports")
      (string-prefix? "transports/" file)))

(define (gateway-relative-path file)
  (let ((prefix (string-append %gateway-root "/")))
    (if (string-prefix? prefix file)
        (substring file (string-length prefix))
        file)))

(define (gateway-source)
  (local-file %gateway-root
              "stogas-gateway-source"
              #:recursive? #t
              #:select?
              (lambda (file stat)
                (let ((relative (gateway-relative-path file)))
                  (and (runtime-source-path? relative)
                       (not (string-contains relative "/.git/"))
                       (not (string-suffix? "/.git" relative))
                       (not (string-contains relative "/tmp/"))
                       (not (string-prefix? "tmp/" relative))
                       (not (string-contains relative "/dist/"))
                       (not (string-contains relative "/node_modules/"))
                       (not (string-contains relative "/transports/vendor/"))
                       (not (string-suffix? "/transports/vendor" relative))
                       (not (string-contains relative "/stogas/release/vendor/"))
                       (not (string-suffix? "/stogas/release/vendor" relative)))))))

(define (source-file path name)
  (local-file (string-append %release-root "/" path) name))

(define (source-directory path name)
  (local-file (string-append %release-root "/" path)
              name
              #:recursive? #t))

(define %go-modcache
  (source-directory "vendor/go-modcache" "stogas-go-modcache"))

(define %go-vendor-sha256
  (source-file "vendor/go-vendor.sha256" "go-vendor.sha256"))

(package
  (name "stogas-gateway-igvm-release")
  (version (substring %release-tag 1))
  (source (gateway-source))
  (build-system trivial-build-system)
  (arguments
   (list
    #:builder
    (with-imported-modules '((guix build utils))
      #~(begin
          (use-modules (guix build utils)
                       (ice-9 match)
                       (ice-9 popen)
                       (ice-9 textual-ports))

          (define (command-output . args)
            (let* ((port (apply open-pipe* OPEN_READ args))
                   (text (get-string-all port))
                   (status (close-pipe port)))
              (unless (zero? status)
                (error "command failed" args))
              text))

	          (define (sha256 path)
	            (car (string-split
	                  (string-trim-right
	                   (command-output "sha256sum" path))
	                  #\space)))

	          (define (write-sha256-lines target inputs)
	            (call-with-output-file target
	              (lambda (port)
	                (for-each
	                 (match-lambda
	                   ((path . store-path)
	                    (format port "~a  ~a~%" (sha256 store-path) path)))
	                 inputs))))

	          (define (tree-sha256 path)
	            (string-trim-both
	             (command-output
	              "bash" "-c"
	              "cd \"$1\" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1"
	              "tree-sha256" path)))

          (define (json-string value)
            (call-with-output-string
             (lambda (port)
               (display "\"" port)
               (string-for-each
                (lambda (char)
                  (case char
                    ((#\") (display "\\\"" port))
                    ((#\\) (display "\\\\" port))
                    ((#\newline) (display "\\n" port))
                    ((#\return) (display "\\r" port))
                    ((#\tab) (display "\\t" port))
                    (else (display char port))))
                value)
               (display "\"" port))))

          (define (launch-digest text)
            (let loop ((lines (string-split text #\newline)))
              (match lines
                (() (error "igvmmeasure output did not contain Launch Digest"))
                ((line . rest)
                 (let ((prefix "Launch Digest: "))
                   (if (string-prefix? prefix line)
                       (substring line (string-length prefix))
                       (loop rest)))))))

	          (define (copy-recursively/quiet source target)
	            (copy-recursively source target
	                              #:log (%make-void-port "w")))

	          (define (write-json-hash-map port inputs)
	            (let loop ((remaining inputs))
	              (match remaining
	                (() #t)
	                (((path . store-path) . rest)
	                 (format port "      ~a: ~a~a\n"
	                         (json-string path)
	                         (json-string (sha256 store-path))
	                         (if (null? rest) "" ","))
	                 (loop rest)))))

	          (define (write-artifact-manifest out igvm efi init kernel initramfs ca-bundle measurement
	                                           vendor-modules build-inputs
	                                           build-inputs-sha256)
            (let* ((pins #$(source-file "pins.lock.json" "pins.lock.json"))
                   (cmdline #$(source-file "guix/cmdline.txt" "cmdline.txt"))
                   (core-go-mod (string-append #$source "/core/go.mod"))
                   (core-go-sum (string-append #$source "/core/go.sum"))
                   (go-mod (string-append #$source "/transports/go.mod"))
                   (go-sum (string-append #$source "/transports/go.sum"))
                   (os-release #$(source-file "guix/os-release" "os-release"))
                   (kernel (string-append #$stogas-linux-6-18 "/bzImage"))
                   (igvmmeasure (string-append #$stogas-igvmmeasure
                                               "/bin/igvmmeasure"))
                   (stub (string-append #$stogas-systemd-uki-tools
                                        "/lib/systemd/boot/efi/linuxx64.efi.stub"))
                   (ovmf (string-append #$stogas-edk2-amdsev-ovmf
                                        "/share/firmware/ovmf-amdsev-x64.fd"))
                   (manifest (string-append out "/release-manifest.json")))
              (call-with-output-file manifest
                (lambda (port)
                  (display "{\n" port)
                  (display "  \"schema\": \"stogas.gateway.release.v1\",\n" port)
                  (format port "  \"sequence\": ~a,\n" #$(release-sequence %release-tag))
                  (display "  \"git\": {\n" port)
                  (format port "    \"commit\": ~a,\n" (json-string #$%release-commit))
                  (format port "    \"ref\": ~a,\n"
                          (json-string (string-append "refs/tags/" #$%release-tag)))
                  (display "    \"repository\": \"https://github.com/StogasAI/gateway\",\n" port)
                  (format port "    \"tag\": ~a,\n" (json-string #$%release-tag))
	                  (format port "    \"tree\": ~a\n" (json-string #$%release-tree))
	                  (display "  },\n" port)
	                  (display "  \"build\": {\n" port)
	                  (format port "    \"buildInputsSha256\": ~a,\n"
	                          (json-string (sha256 build-inputs-sha256)))
	                  (display "    \"environment\": {\n" port)
	                  (display "      \"lcAll\": \"C\",\n" port)
	                  (display "      \"sourceDateEpoch\": \"1\",\n" port)
	                  (display "      \"tz\": \"UTC\",\n" port)
	                  (display "      \"umask\": \"022\"\n" port)
	                  (display "    },\n" port)
	                  (format port "    \"cmdlineSha256\": ~a,\n" (json-string (sha256 cmdline)))
	                  (format port "    \"coreGoModSha256\": ~a,\n" (json-string (sha256 core-go-mod)))
	                  (format port "    \"coreGoSumSha256\": ~a,\n" (json-string (sha256 core-go-sum)))
	                  (format port "    \"goModSha256\": ~a,\n" (json-string (sha256 go-mod)))
	                  (format port "    \"goSumSha256\": ~a,\n" (json-string (sha256 go-sum)))
	                  (format port "    \"goVendorModulesSha256\": ~a,\n" (json-string (sha256 vendor-modules)))
	                  (format port "    \"goVendorTreeSha256\": ~a,\n"
	                          (json-string expected-go-vendor-tree-sha256))
	                  (format port "    \"goVersion\": ~a,\n"
	                          (json-string (string-trim-right (command-output "go" "version"))))
	                  (format port "    \"guestCaBundlePath\": ~a,\n"
	                          (json-string "/etc/ssl/certs/ca-certificates.crt"))
	                  (format port "    \"guestCaBundleSha256\": ~a,\n"
	                          (json-string (sha256 ca-bundle)))
                  (display "    \"guixChannelCommit\": \"d1e9e23fd441fce828fa74616271b00b90853cee\",\n" port)
                  (format port "    \"kernelConfigSha256\": ~a,\n"
                          (json-string (sha256 (string-append #$stogas-linux-6-18 "/.config"))))
                  (display "    \"kernelVersion\": \"6.18.35\",\n" port)
                  (format port "    \"linuxBzImageSha256\": ~a,\n" (json-string (sha256 kernel)))
                  (format port "    \"osReleaseSha256\": ~a,\n" (json-string (sha256 os-release)))
	                  (format port "    \"ovmfSha256\": ~a,\n" (json-string (sha256 ovmf)))
	                  (format port "    \"pinsLockSha256\": ~a,\n" (json-string (sha256 pins)))
	                  (format port "    \"systemdStubSha256\": ~a,\n" (json-string (sha256 stub)))
	                  (format port "    \"ukiSha256\": ~a,\n" (json-string (sha256 efi)))
	                  (display "    \"inputSha256\": {\n" port)
	                  (write-json-hash-map port build-inputs)
	                  (display "    }\n" port)
	                  (display "  },\n" port)
	                  (display "  \"artifacts\": {\n" port)
	                  (display "    \"gateway.igvm\": {\n" port)
                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 igvm)))
                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat igvm)))
                  (display "    },\n" port)
	                  (display "    \"gateway.efi\": {\n" port)
	                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 efi)))
	                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat efi)))
	                  (display "    },\n" port)
	                  (display "    \"gateway.init\": {\n" port)
	                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 init)))
	                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat init)))
	                  (display "    },\n" port)
	                  (display "    \"gateway.kernel\": {\n" port)
	                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 kernel)))
	                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat kernel)))
	                  (display "    },\n" port)
	                  (display "    \"gateway.initramfs.cpio.zst\": {\n" port)
	                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 initramfs)))
	                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat initramfs)))
	                  (display "    }\n" port)
                  (display "  },\n" port)
                  (display "  \"sevSnp\": {\n" port)
                  (display "    \"platform\": \"SEV_SNP\",\n" port)
                  (display "    \"vmm\": \"qemu-kvm\",\n" port)
                  (display "    \"measurementTool\": \"igvmmeasure\",\n" port)
                  (format port "    \"measurementToolVersion\": ~a,\n"
                          (json-string #$(package-version stogas-igvmmeasure)))
                  (format port "    \"measurementToolSha256\": ~a,\n"
                          (json-string (sha256 igvmmeasure)))
                  (display "    \"measurementCommand\": \"igvmmeasure --check-kvm gateway.igvm measure\",\n" port)
                  (display "    \"checkKvm\": true,\n" port)
                  (format port "    \"launchMeasurement\": ~a\n"
                          (json-string (string-trim-both measurement)))
                  (display "  }\n" port)
                  (display "}\n" port)))))

          (define out #$output)
          (define source #$source)
          (define work (string-append (getcwd) "/work"))
          (define build-source (string-append work "/source"))
          (define go-modcache (string-append work "/go-modcache"))
          (define rootfs (string-append work "/rootfs"))
	          (define initramfs (string-append work "/initramfs.cpio.zst"))
	          (define efi (string-append out "/gateway.efi"))
	          (define igvm (string-append out "/gateway.igvm"))
	          (define init (string-append out "/gateway.init"))
	          (define release-kernel (string-append out "/gateway.kernel"))
	          (define release-initramfs (string-append out "/gateway.initramfs.cpio.zst"))
	          (define measurement-path (string-append out "/launch-measurement.txt"))
	          (define igvmmeasure-check-kvm
	            (string-append out "/igvmmeasure-check-kvm.txt"))
	          (define ukify-inspect (string-append out "/ukify-inspect.txt"))
	          (define kernel-config (string-append out "/kernel-config.txt"))
	          (define build-inputs-sha256 (string-append out "/build-inputs.sha256"))
	          (define pins #$(source-file "pins.lock.json" "pins.lock.json"))
	          (define expected-go-vendor-tree-sha256
	            (string-trim-both
	             (call-with-input-file #$%go-vendor-sha256 get-string-all)))
	          (define os-release #$(source-file "guix/os-release" "os-release"))
	          (define ukify (string-append #$stogas-systemd-uki-tools "/bin/ukify"))
          (define stub (string-append #$stogas-systemd-uki-tools
                                      "/lib/systemd/boot/efi/linuxx64.efi.stub"))
	          (define kernel (string-append #$stogas-linux-6-18 "/bzImage"))
	          (define ovmf (string-append #$stogas-edk2-amdsev-ovmf
	                                      "/share/firmware/ovmf-amdsev-x64.fd"))
	          (define ca-bundle
	            #$(file-append (pkg "nss-certs")
	                           "/etc/ssl/certs/ca-certificates.crt"))
	          (define rootfs-ca-bundle
	            (string-append rootfs "/etc/ssl/certs/ca-certificates.crt"))
	          (define build-inputs
	            (list
	             (cons "stogas/release/guix/channels.scm"
	                   #$(source-file "guix/channels.scm" "channels.scm"))
	             (cons "stogas/release/guix/release.scm"
	                   #$(source-file "guix/release.scm" "release.scm"))
	             (cons "stogas/release/guix/modules/stogas/release/packages.scm"
	                   #$(source-file "guix/modules/stogas/release/packages.scm"
	                                  "packages.scm"))
	             (cons "stogas/release/scripts/build-release.sh"
	                   #$(source-file "scripts/build-release.sh" "build-release.sh"))
	             (cons "stogas/release/scripts/fetch-sigstore-trust-bundle.mjs"
	                   #$(source-file "scripts/fetch-sigstore-trust-bundle.mjs"
	                                  "fetch-sigstore-trust-bundle.mjs"))
	             (cons "stogas/release/scripts/hydrate-go-vendor.sh"
	                   #$(source-file "scripts/hydrate-go-vendor.sh"
	                                  "hydrate-go-vendor.sh"))
	             (cons "stogas/release/scripts/hydrate-guix-closure.sh"
	                   #$(source-file "scripts/hydrate-guix-closure.sh"
	                                  "hydrate-guix-closure.sh"))
	             (cons "stogas/release/scripts/hydrate-rust-vendor.sh"
	                   #$(source-file "scripts/hydrate-rust-vendor.sh"
	                                  "hydrate-rust-vendor.sh"))
	             (cons "stogas/release/scripts/install-guix-bootstrap.sh"
	                   #$(source-file "scripts/install-guix-bootstrap.sh"
	                                  "install-guix-bootstrap.sh"))
	             (cons "stogas/release/scripts/verify-pins.mjs"
	                   #$(source-file "scripts/verify-pins.mjs" "verify-pins.mjs"))
	             (cons "stogas/release/patches/svsm-igvmmeasure-standalone-cargo.patch"
	                   #$(source-file "patches/svsm-igvmmeasure-standalone-cargo.patch"
	                                  "svsm-igvmmeasure-standalone-cargo.patch"))
	             (cons "stogas/release/patches/virt-firmware-rs-kvm-vmsa-last.patch"
	                   #$(source-file "patches/virt-firmware-rs-kvm-vmsa-last.patch"
	                                  "virt-firmware-rs-kvm-vmsa-last.patch"))
	             (cons "stogas/release/locks/igvmmeasure.Cargo.lock"
	                   #$(source-file "locks/igvmmeasure.Cargo.lock"
	                                  "igvmmeasure.Cargo.lock"))
	             (cons "stogas/release/locks/virt-firmware-rs.Cargo.lock"
	                   #$(source-file "locks/virt-firmware-rs.Cargo.lock"
	                                  "virt-firmware-rs.Cargo.lock"))
	             (cons "core/go.mod"
	                   (string-append #$source "/core/go.mod"))
	             (cons "core/go.sum"
	                   (string-append #$source "/core/go.sum"))
	             (cons "transports/go.mod"
	                   (string-append #$source "/transports/go.mod"))
	             (cons "transports/go.sum"
	                   (string-append #$source "/transports/go.sum"))
	             (cons "guix/nss-certs/ca-certificates.crt"
	                   ca-bundle)
	             (cons "stogas/release/vendor/go-vendor.sha256"
	                   #$%go-vendor-sha256)
	             (cons "stogas/release/pins.lock.json"
	                   pins)))

	          (setenv "SOURCE_DATE_EPOCH" "1")
	          (setenv "LC_ALL" "C")
	          (setenv "TZ" "UTC")
          (setenv "GOPROXY" "off")
          (setenv "GOSUMDB" "off")
          (setenv "GOTOOLCHAIN" "local")
          (setenv "GOWORK" "off")
          (setenv "CGO_ENABLED" "0")
          (setenv "HOME" work)
          (setenv "GOMODCACHE" go-modcache)
          (setenv "GOCACHE" (string-append work "/go-build-cache"))
          (setenv "PATH"
                  (string-append #$(file-append (pkg "bash-minimal") "/bin") ":"
                                 #$(file-append (pkg "coreutils") "/bin") ":"
                                 #$(file-append (pkg "cpio") "/bin") ":"
                                 #$(file-append (pkg "findutils") "/bin") ":"
                                 #$(file-append (pkg "grep") "/bin") ":"
                                 #$(file-append (pkg "go@1.26") "/bin") ":"
                                 #$(file-append (pkg "gzip") "/bin") ":"
                                 #$(file-append (pkg "sed") "/bin") ":"
                                 #$(file-append (pkg "tar") "/bin") ":"
                                 #$(file-append (pkg "zstd") "/bin") ":"
                                 #$(file-append stogas-igvmmeasure "/bin") ":"
	                                 #$(file-append stogas-virt-firmware-rs-tools "/bin")))

	          (mkdir-p out)
	          (umask #o022)
	          (mkdir-p work)
          (copy-recursively/quiet source build-source)
          (invoke "chmod" "-R" "u+w" build-source)
          (copy-recursively/quiet #$%go-modcache go-modcache)
          (invoke "chmod" "-R" "u+w" go-modcache)
          (mkdir-p rootfs)
	          (mkdir-p (dirname rootfs-ca-bundle))
	          (copy-file ca-bundle rootfs-ca-bundle)
	          (chmod rootfs-ca-bundle #o444)
	          (with-directory-excursion (string-append build-source "/transports")
	            (when (file-exists? "vendor")
	              (delete-file-recursively "vendor"))
	            (invoke "bash" "-c" "sha256sum go.mod go.sum > /tmp/go-before.sha256")
	            (invoke "go" "mod" "verify")
	            (invoke "go" "mod" "vendor")
	            (invoke "sha256sum" "-c" "/tmp/go-before.sha256")
	            (let ((actual-go-vendor-tree-sha256 (tree-sha256 "vendor")))
	              (unless (string=? actual-go-vendor-tree-sha256
	                                expected-go-vendor-tree-sha256)
	                (error "Go vendor tree hash mismatch"
	                       actual-go-vendor-tree-sha256
	                       expected-go-vendor-tree-sha256)))
	            (invoke "go" "build"
                    "-trimpath"
                    "-buildvcs=false"
                    "-ldflags=-buildid= -s -w"
                    "-mod=vendor"
                    "-o" (string-append rootfs "/init")
                    "./cmd/stogas-gateway"))
          (chmod (string-append rootfs "/init") #o555)
          (invoke "find" rootfs "-exec" "touch" "-h" "-d" "@1" "{}" "+")
          (invoke "bash" "-c"
                  (string-append "cd " rootfs
	                                 " && find . -print0 | sort -z"
	                                 " | cpio --null --reproducible -o"
	                                 " --format=newc --owner=0:0"
	                                 " | zstd -19 -T1 --no-progress -o "
	                                 initramfs))
	          (copy-file (string-append rootfs "/init") init)
	          (copy-file kernel release-kernel)
	          (copy-file initramfs release-initramfs)
	          (invoke ukify "build"
                  "--stub" stub
                  "--linux" kernel
                  "--initrd" initramfs
                  "--os-release" (string-append "@" os-release)
                  "--uname" "6.18.35-stogas"
	                  "--cmdline" (string-append "@" #$(source-file "guix/cmdline.txt"
	                                                                 "cmdline.txt"))
	                  "--output" efi)
	          (call-with-output-file ukify-inspect
	            (lambda (port)
	              (display (command-output ukify "inspect" efi) port)))
	          (invoke "igvm-wrap"
                  "--input" ovmf
                  "--snp"
                  "--flat32"
                  "--output" (string-append work "/base.igvm"))
          (invoke "igvm-update"
                  "--input" (string-append work "/base.igvm")
                  "--kernel" efi
	                  "--add-hash-sha256"
	                  "--profile" "none"
	                  "--output" igvm)
	          (call-with-output-file igvmmeasure-check-kvm
	            (lambda (port)
	              (display (command-output "igvmmeasure" "--check-kvm" igvm "measure")
	                       port)))
	          (call-with-output-file measurement-path
	            (lambda (port)
	              (display (launch-digest
	                        (call-with-input-file igvmmeasure-check-kvm
	                                              get-string-all))
	                       port)
	              (newline port)))
	          (copy-file pins (string-append out "/pins.lock.json"))
	          (copy-file (string-append #$stogas-linux-6-18 "/.config") kernel-config)
	          (write-sha256-lines build-inputs-sha256 build-inputs)
	          (write-artifact-manifest
	           out
	           igvm
	           efi
	           init
	           release-kernel
	           release-initramfs
	           ca-bundle
	           (call-with-input-file measurement-path get-string-all)
	           (string-append build-source "/transports/vendor/modules.txt")
	           build-inputs
	           build-inputs-sha256)
          (call-with-output-file (string-append out "/SHA256SUMS")
            (lambda (port)
              (for-each
               (lambda (file)
                 (format port "~a  ~a~%" (sha256 (string-append out "/" file)) file))
	               '("gateway.igvm"
	                 "gateway.efi"
	                 "gateway.init"
	                 "gateway.kernel"
	                 "gateway.initramfs.cpio.zst"
	                 "launch-measurement.txt"
	                 "release-manifest.json"
	                 "pins.lock.json"
	                 "igvmmeasure-check-kvm.txt"
	                 "ukify-inspect.txt"
	                 "kernel-config.txt"
	                 "build-inputs.sha256"))))))))
  (native-inputs
   (list (pkg "bash-minimal")
         (pkg "coreutils")
         (pkg "cpio")
         (pkg "findutils")
         (pkg "go@1.26")
         (pkg "grep")
         (pkg "gzip")
         (pkg "nss-certs")
         (pkg "sed")
         (pkg "tar")
         (pkg "zstd")
         stogas-edk2-amdsev-ovmf
         stogas-igvmmeasure
         stogas-linux-6-18
         stogas-systemd-uki-tools
         stogas-virt-firmware-rs-tools))
  (synopsis "Deterministic Stogas gateway IGVM release")
  (description "Builds the gateway Go payload, initramfs, UKI, AmdSev IGVM,
SEV-SNP launch measurement, manifest, and checksums as one Guix derivation.")
  (home-page "https://stogas.ai")
  (license #f))
