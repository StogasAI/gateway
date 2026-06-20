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

          (define (write-artifact-manifest out igvm efi measurement vendor-modules)
            (let* ((pins #$(source-file "pins.lock.json" "pins.lock.json"))
                   (cmdline #$(source-file "guix/cmdline.txt" "cmdline.txt"))
                   (go-mod (string-append #$source "/transports/go.mod"))
                   (go-sum (string-append #$source "/transports/go.sum"))
                   (os-release #$(source-file "guix/os-release" "os-release"))
                   (kernel (string-append #$stogas-linux-6-18 "/bzImage"))
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
                  (format port "    \"cmdlineSha256\": ~a,\n" (json-string (sha256 cmdline)))
                  (format port "    \"goModSha256\": ~a,\n" (json-string (sha256 go-mod)))
                  (format port "    \"goSumSha256\": ~a,\n" (json-string (sha256 go-sum)))
                  (format port "    \"goVendorModulesSha256\": ~a,\n" (json-string (sha256 vendor-modules)))
                  (format port "    \"goVersion\": ~a,\n"
                          (json-string (string-trim-right (command-output "go" "version"))))
                  (display "    \"guixChannelCommit\": \"d1e9e23fd441fce828fa74616271b00b90853cee\",\n" port)
                  (format port "    \"kernelConfigSha256\": ~a,\n"
                          (json-string (sha256 (string-append #$stogas-linux-6-18 "/.config"))))
                  (display "    \"kernelVersion\": \"6.18.35\",\n" port)
                  (format port "    \"linuxBzImageSha256\": ~a,\n" (json-string (sha256 kernel)))
                  (format port "    \"osReleaseSha256\": ~a,\n" (json-string (sha256 os-release)))
                  (format port "    \"ovmfSha256\": ~a,\n" (json-string (sha256 ovmf)))
                  (format port "    \"pinsLockSha256\": ~a,\n" (json-string (sha256 pins)))
                  (display "    \"sourceDateEpoch\": \"1\",\n" port)
                  (format port "    \"systemdStubSha256\": ~a,\n" (json-string (sha256 stub)))
                  (format port "    \"ukiSha256\": ~a\n" (json-string (sha256 efi)))
                  (display "  },\n" port)
                  (display "  \"artifacts\": {\n" port)
                  (display "    \"gateway.igvm\": {\n" port)
                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 igvm)))
                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat igvm)))
                  (display "    },\n" port)
                  (display "    \"gateway.efi\": {\n" port)
                  (format port "      \"sha256\": ~a,\n" (json-string (sha256 efi)))
                  (format port "      \"sizeBytes\": ~a\n" (stat:size (stat efi)))
                  (display "    }\n" port)
                  (display "  },\n" port)
                  (display "  \"sevSnp\": {\n" port)
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
          (define measurement-path (string-append out "/launch-measurement.txt"))
          (define pins #$(source-file "pins.lock.json" "pins.lock.json"))
          (define os-release #$(source-file "guix/os-release" "os-release"))
          (define ukify (string-append #$stogas-systemd-uki-tools "/bin/ukify"))
          (define stub (string-append #$stogas-systemd-uki-tools
                                      "/lib/systemd/boot/efi/linuxx64.efi.stub"))
          (define kernel (string-append #$stogas-linux-6-18 "/bzImage"))
          (define ovmf (string-append #$stogas-edk2-amdsev-ovmf
                                      "/share/firmware/ovmf-amdsev-x64.fd"))

          (setenv "SOURCE_DATE_EPOCH" "1")
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
          (mkdir-p work)
          (copy-recursively/quiet source build-source)
          (invoke "chmod" "-R" "u+w" build-source)
          (copy-recursively/quiet #$%go-modcache go-modcache)
          (invoke "chmod" "-R" "u+w" go-modcache)
          (mkdir-p rootfs)
          (with-directory-excursion (string-append build-source "/transports")
            (when (file-exists? "vendor")
              (delete-file-recursively "vendor"))
            (invoke "go" "mod" "verify")
            (invoke "go" "mod" "vendor")
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
                                 " | zstd -19 --no-progress -o "
                                 initramfs))
          (invoke ukify "build"
                  "--stub" stub
                  "--linux" kernel
                  "--initrd" initramfs
                  "--os-release" (string-append "@" os-release)
                  "--uname" "6.18.35-stogas"
                  "--cmdline" (string-append "@" #$(source-file "guix/cmdline.txt"
                                                                 "cmdline.txt"))
                  "--output" efi)
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
          (call-with-output-file measurement-path
            (lambda (port)
              (display (launch-digest
                        (command-output "igvmmeasure" "--check-kvm" igvm "measure"))
                       port)
              (newline port)))
          (copy-file pins (string-append out "/pins.lock.json"))
          (write-artifact-manifest
           out
           igvm
           efi
           (call-with-input-file measurement-path get-string-all)
           (string-append build-source "/transports/vendor/modules.txt"))
          (call-with-output-file (string-append out "/SHA256SUMS")
            (lambda (port)
              (for-each
               (lambda (file)
                 (format port "~a  ~a~%" (sha256 (string-append out "/" file)) file))
               '("gateway.igvm"
                 "gateway.efi"
                 "launch-measurement.txt"
                 "release-manifest.json"
                 "pins.lock.json"))))))))
  (native-inputs
   (list (pkg "bash-minimal")
         (pkg "coreutils")
         (pkg "cpio")
         (pkg "findutils")
         (pkg "go@1.26")
         (pkg "grep")
         (pkg "gzip")
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
