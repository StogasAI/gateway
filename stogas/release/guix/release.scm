(use-modules (gnu packages)
             (guix build-system trivial)
             (guix channels)
             (guix describe)
             (guix gexp)
             ((guix licenses) #:prefix license:)
             (guix packages)
             (ice-9 match)
             (stogas release packages))

(define %release-root (dirname (dirname (current-filename))))
(define %gateway-root (dirname (dirname %release-root)))

(define (release-file path)
  (local-file (string-append %release-root "/" path)))

(define (gateway-file path)
  (local-file (string-append %gateway-root "/" path) #:recursive? #t))

(define (environment name)
  (or (getenv name) (error "missing release environment variable" name)))

(define %tag (environment "STOGAS_RELEASE_TAG"))

;; The build must run the Guix that channels.scm pins and no other channel.
(define %guix-commit
  (match (current-channels)
    ((channel) (channel-commit channel))))

(define %gcc (specification->package "gcc-toolchain"))

(package
  (name "stogas-gateway-igvm-release")
  (version (substring %tag 1))
  (source #f)
  (build-system trivial-build-system)
  (arguments
   (list
    #:builder
    (with-extensions (list (specification->package "guile-json@4"))
      (with-imported-modules '((guix build utils))
        #~(begin
            (use-modules (guix build utils)
                         (ice-9 ftw)
                         (ice-9 match)
                         (ice-9 popen)
                         (ice-9 textual-ports)
                         (json))

            (define (output-of . command)
              (let* ((port (apply open-pipe* OPEN_READ command))
                     (text (get-string-all port)))
                (unless (zero? (close-pipe port))
                  (error "command failed" command))
                (string-trim-right text)))

            (define (sha256 file)
              (car (string-split (output-of "sha256sum" file) #\space)))

            ;; Canonical JSON sorts object keys.
            (define (canonical value)
              (cond
               ((vector? value)
                (list->vector (map canonical (vector->list value))))
               ((pair? value)
                (sort (map (match-lambda
                             ((key . item) (cons key (canonical item))))
                           value)
                      (lambda (a b) (string<? (car a) (car b)))))
               (else value)))

            (define work (string-append (getcwd) "/work"))
            (define source (string-append work "/source"))
            (define rootfs (string-append work "/rootfs"))
            (define ca-bundle
              (string-append rootfs "/etc/ssl/certs/ca-certificates.crt"))
            (define initramfs (string-append work "/initramfs.cpio.zst"))
            (define uki (string-append work "/gateway.efi"))
            (define igvm (string-append #$output "/gateway.igvm"))
            (define kernel #$(file-append stogas-linux "/bzImage"))
            (define kernel-config #$(file-append stogas-linux "/.config"))
            (define ovmf #$(file-append stogas-ovmf "/share/firmware/OVMF.fd"))
            (define stub
              #$(file-append stogas-systemd-uki-tools
                             "/lib/systemd/boot/efi/linuxx64.efi.stub"))
            (define igvmmeasure
              #$(file-append stogas-igvmmeasure "/bin/igvmmeasure"))
            (define cmdline #$(release-file "guix/cmdline.txt"))
            (define ntp-config #$(release-file "guix/ntp.toml"))
            (define os-release #$(release-file "guix/os-release"))
            (define launch-policies #$(release-file "snp-launch-policies.json"))
            ;; Verifiers bind the embedded launch policies to the hash of
            ;; this file, so the file must be canonical JSON.
            (define launch-policies-value
              (canonical (call-with-input-file launch-policies json->scm)))
            (unless (string=? (call-with-input-file launch-policies get-string-all)
                              (string-append
                               (scm->json-string launch-policies-value) "\n"))
              (error "snp-launch-policies.json is not canonical JSON"))

            (setenv "PATH"
                    (string-join
                     (map (lambda (directory) (string-append directory "/bin"))
                          '#$(list (specification->package "bash-minimal")
                                   (specification->package "coreutils")
                                   (specification->package "cpio")
                                   (specification->package "findutils")
                                   (specification->package "zstd")
                                   %gcc
                                   stogas-go))
                     ":"))
            (setenv "LC_ALL" "C")
            (setenv "TZ" "UTC")
            (setenv "SOURCE_DATE_EPOCH" "1")
            (setenv "HOME" work)
            (setenv "GOCACHE" (string-append work "/go-cache"))
            (setenv "GOTOOLCHAIN" "local")
            (setenv "C_INCLUDE_PATH" #$(file-append %gcc "/include"))
            (setenv "CGO_LDFLAGS"
                    (string-append "-L" #$(file-append stogas-verifier "/lib")
                                   " -L" (ungexp %gcc "static") "/lib"))
            (umask #o022)
            (mkdir-p #$output)

            (for-each
             (match-lambda
               ((name directory)
                (copy-recursively directory (string-append source "/" name)
                                  #:log (%make-void-port "w"))))
             '(("core" #$(gateway-file "core"))
               ("transports" #$(gateway-file "transports"))))

            (for-each (lambda (directory)
                        (mkdir-p (string-append rootfs directory)))
                      '("/etc/ntpd-rs" "/etc/ssl/certs" "/stogas"))
            ;; Kernel DHCP writes the resolver settings to /proc/net/pnp
            ;; before init starts, so one image works in every subnet.
            (symlink "/proc/net/pnp" (string-append rootfs "/etc/resolv.conf"))
            (let ((certificates #$(file-append
                                   (specification->package "nss-certs")
                                   "/etc/ssl/certs")))
              (call-with-output-file ca-bundle
                (lambda (port)
                  (for-each
                   (lambda (name)
                     (display (call-with-input-file
                                  (string-append certificates "/" name)
                                get-string-all)
                              port)
                     (newline port))
                   (scandir certificates
                            (lambda (name) (string-suffix? ".pem" name))
                            string<?)))))
            (copy-file ntp-config (string-append rootfs "/etc/ntpd-rs/ntp.toml"))
            (copy-file #$(file-append stogas-ntpd-rs "/bin/ntp-daemon")
                       (string-append rootfs "/stogas/ntp-daemon"))

            (with-directory-excursion (string-append source "/transports")
              (setenv "CGO_ENABLED" "1")
              (invoke "go" "build" "-trimpath" "-mod=vendor"
                      "-tags=stogas_gateway,netgo,osusergo"
                      (string-append
                       "-ldflags=-s -w -linkmode=external"
                       " -extldflags \"-static -Wl,--gc-sections,--build-id=none\""
                       " -X github.com/maximhq/bifrost/transports/stogas.GatewayVersion="
                       #$%tag)
                      "-o" (string-append rootfs "/stogas/gateway.init")
                      "./cmd/stogas-gateway")
              (setenv "CGO_ENABLED" "0")
              (invoke "go" "build" "-trimpath" "-mod=vendor"
                      (string-append "-ldflags=-s -w -X main.releaseTime="
                                     #$(environment "STOGAS_RELEASE_TIME"))
                      "-o" (string-append rootfs "/init")
                      "./cmd/stogas-gateway-init"))

            (for-each (match-lambda
                        ((file mode)
                         (chmod (string-append rootfs file) mode)))
                      '(("/etc/ntpd-rs/ntp.toml" #o444)
                        ("/etc/ssl/certs/ca-certificates.crt" #o444)
                        ("/init" #o555)
                        ("/stogas/gateway.init" #o555)
                        ("/stogas/ntp-daemon" #o555)))
            (invoke "find" rootfs "-exec" "touch" "--no-dereference"
                    "--date=@1" "{}" "+")
            (with-directory-excursion rootfs
              (invoke "bash" "-c"
                      (string-append
                       "set -o pipefail; find . -print0 | sort -z"
                       " | cpio --null --reproducible --create --format=newc"
                       " --owner=0:0 | zstd -19 -T1 --no-progress -o "
                       initramfs)))

            (invoke #$(file-append stogas-systemd-uki-tools "/bin/ukify")
                    "build" "--stub" stub "--linux" kernel "--initrd" initramfs
                    "--os-release" (string-append "@" os-release)
                    "--cmdline" (string-append "@" cmdline)
                    "--output" uki)
            (invoke #$(file-append stogas-virt-firmware-rs "/bin/igvm-wrap")
                    "--input" ovmf "--snp" "--no-native" "--cpus" "4"
                    "--output" (string-append work "/base.igvm"))
            ;; Without Secure Boot options, igvm-update adds the UKI as
            ;; measured pages, so the launch measurement covers it.
            (invoke #$(file-append stogas-virt-firmware-rs "/bin/igvm-update")
                    "--input" (string-append work "/base.igvm")
                    "--kernel" uki "--output" igvm)
            ;; The host can change unmeasured or shared pages without
            ;; changing the launch measurement.
            (let* ((pages (filter (lambda (line)
                                    (string-prefix? "PageData: gpa" line))
                                  (string-split
                                   (output-of
                                    #$(file-append stogas-virt-firmware-rs
                                                   "/bin/igvm-inspect")
                                    igvm)
                                   #\newline)))
                   (exposed (filter (lambda (line)
                                      (or (string-contains line ", unmeasured")
                                          (string-contains line ", shared")))
                                    pages)))
              (unless (and (pair? pages) (null? exposed))
                (error "IGVM has unmeasured or shared pages" exposed)))

            (for-each (match-lambda
                        ((file target)
                         (copy-file file (string-append #$output "/" target))))
                      `((,(string-append rootfs "/stogas/gateway.init")
                         "gateway.init")
                        (,kernel "gateway.kernel")
                        (,initramfs "gateway.initramfs.cpio.zst")
                        (,kernel-config "kernel-config.txt")
                        (#$(gateway-file "LICENSE") "LICENSE")
                        (#$(gateway-file "NOTICE") "NOTICE")))

            (call-with-output-file (string-append #$output "/release-manifest.json")
              (lambda (port)
                (scm->json
                 (canonical
                  `(("artifacts"
                     ("gateway.igvm"
                      ("sha256" . ,(sha256 igvm))
                      ("size_bytes" . ,(stat:size (stat igvm)))))
                    ("build"
                     ("environment"
                      ("lc_all" . "C")
                      ("source_date_epoch" . "1")
                      ("tz" . "UTC")
                      ("umask" . "022"))
                     ("go_vendor_tree_sha256"
                      . #$(environment "STOGAS_RELEASE_VENDOR_SHA256"))
                     ("go_version" . ,(output-of "go" "version"))
                     ("guest_ca_bundle_path" . "/etc/ssl/certs/ca-certificates.crt")
                     ("guix_channel_commit" . #$%guix-commit)
                     ("input_sha256"
                      ,@(map (match-lambda
                               ((name . file) (cons name (sha256 file))))
                             `(("core/go.mod" . ,(string-append source "/core/go.mod"))
                               ("core/go.sum" . ,(string-append source "/core/go.sum"))
                               ("transports/go.mod"
                                . ,(string-append source "/transports/go.mod"))
                               ("transports/go.sum"
                                . ,(string-append source "/transports/go.sum"))
                               ("guix/nss-certs/ca-certificates.crt" . ,ca-bundle)
                               ("stogas/release/guix/cmdline.txt" . ,cmdline)
                               ("stogas/release/guix/ntp.toml" . ,ntp-config)
                               ("stogas/release/guix/os-release" . ,os-release)
                               ("stogas/release/pins.lock.json"
                                . #$(release-file "pins.lock.json"))
                               ("stogas/release/snp-launch-policies.json"
                                . ,launch-policies)))
                      ("verifier/source"
                       . #$(environment "STOGAS_RELEASE_VERIFIER_SHA256")))
                     ("kernel_config_sha256" . ,(sha256 kernel-config))
                     ("kernel_version" . #$(package-version stogas-linux))
                     ("linux_bz_image_sha256" . ,(sha256 kernel))
                     ("ovmf_sha256" . ,(sha256 ovmf))
                     ("systemd_stub_sha256" . ,(sha256 stub))
                     ("uki_sha256" . ,(sha256 uki)))
                    ("schema" . "stogas.gateway.release.v1")
                    ("sequence" . #$(string->number
                                     (environment "STOGAS_RELEASE_SEQUENCE")))
                    ("sev_snp"
                     ("check_kvm" . #t)
                     ("launch_measurement"
                      . ,(string-downcase
                          (output-of igvmmeasure "--check-kvm" igvm
                                     "measure" "--bare")))
                     ("launch_policies" . ,launch-policies-value)
                     ("measurement_command"
                      . "igvmmeasure --check-kvm gateway.igvm measure")
                     ("measurement_tool" . "igvmmeasure")
                     ("measurement_tool_sha256" . ,(sha256 igvmmeasure))
                     ("measurement_tool_version"
                      . #$(package-version stogas-igvmmeasure))
                     ("platform" . "SEV_SNP")
                     ("vcpu_count" . 4)
                     ("vmm" . "qemu-kvm"))
                    ("source"
                     ("commit" . #$(environment "STOGAS_RELEASE_COMMIT"))
                     ("repository" . "https://github.com/StogasAI/gateway")
                     ("sha256" . #$(environment "STOGAS_RELEASE_SOURCE_SHA256"))
                     ("tag" . #$%tag))))
                 port)
                (newline port))))))))
  (home-page "https://github.com/StogasAI/gateway")
  (synopsis "Stogas gateway IGVM release")
  (description "The SEV-SNP gateway IGVM image, its launch measurement, and
the release manifest that records how it was built.")
  (license license:asl2.0))
