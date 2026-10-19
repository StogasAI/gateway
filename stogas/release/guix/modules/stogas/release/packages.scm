(define-module (stogas release packages)
  #:use-module (gnu packages)
  #:use-module ((gnu packages firmware) #:select (ovmf-x86-64))
  #:use-module ((gnu packages rust) #:select (rust-1.95))
  #:use-module (guix base16)
  #:use-module (guix base32)
  #:use-module ((guix build-system cargo) #:select (crate-name->package-name
                                                   crate-uri))
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system meson)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (ice-9 match)
  #:use-module (ice-9 rdelim)
  #:use-module (ice-9 regex)
  #:use-module (json)
  #:use-module (srfi srfi-1)
  #:export (stogas-go
            stogas-igvmmeasure
            stogas-linux
            stogas-ntpd-rs
            stogas-ovmf
            stogas-systemd-uki-tools
            stogas-verifier
            stogas-virt-firmware-rs))

;; Guix commands load this module without compiling it, so current-filename
;; is unknown; find the module on the load path instead.
(define %release-root
  (let ((file (search-path %load-path "stogas/release/packages.scm")))
    (dirname (dirname (dirname (dirname (dirname (canonicalize-path file))))))))

(define (release-path path)
  (string-append %release-root "/" path))

(define (release-file path)
  (local-file (release-path path)))

(define (patch-file name)
  (release-file (string-append "patches/" name)))

(define %sources
  (assoc-ref (call-with-input-file (release-path "pins.lock.json") json->scm)
             "releaseSources"))

(define (pin source field)
  (or (and=> (assoc-ref %sources source)
             (lambda (fields) (assoc-ref fields field)))
      (error "missing release pin" source field)))

(define* (pinned-git-origin source url #:key (name source)
                            (version (pin source "version"))
                            recursive? (patches '()))
  (origin
    (method git-fetch)
    (uri (git-reference
          (url url)
          (commit (pin source "commit"))
          (recursive? recursive?)))
    (file-name (git-file-name name version))
    (sha256 (nix-base32-string->bytevector (pin source "narSha256")))
    (patches patches)
    (patch-flags '("-p1" "--fuzz=0"))))

(define stogas-go
  (let ((base (specification->package
               (string-append "go@" (version-major+minor (pin "go" "version"))))))
    (package
      (inherit base)
      (version (pin "go" "version"))
      (source (pinned-git-origin "go" "https://github.com/golang/go")))))

(define stogas-linux
  (let ((base (specification->package
               (string-append "linux-libre@" (pin "linux" "version"))))
        (config (release-file "guix/linux.config")))
    (package
      (inherit base)
      (name "stogas-linux")
      ;; This drops Guix's kernel patches, which add a boot logo and an ARM
      ;; export that this x86 kernel does not build.
      (source
       (origin
         (inherit (package-source base))
         (patches '())))
      (arguments
       (substitute-keyword-arguments (package-arguments base)
         ((#:imported-modules modules %default-gnu-imported-modules)
          `((guix build kconfig) ,@modules))
         ((#:modules modules)
          `((guix build kconfig) ,@modules))
         ((#:phases phases)
          #~(modify-phases #$phases
              (replace 'configure
                (lambda _
                  ;; Guix sets this to SOURCE_DATE_EPOCH, "1", which `date -d`
                  ;; reads as 01:00 today when dating the built-in initramfs.
                  (setenv "KBUILD_BUILD_TIMESTAMP" "1970-01-01 00:00:01 UTC")
                  (invoke "make" "allnoconfig"
                          (string-append "KCONFIG_ALLCONFIG=" #$config))
                  (verify-config ".config" #$config)))))))
      (synopsis "Linux kernel for the Stogas SEV-SNP gateway guest")
      (description
       "Linux-libre configured from @code{allnoconfig} with only the options
that the diskless SEV-SNP gateway guest uses."))))

(define stogas-systemd-uki-tools
  (package
    (name "stogas-systemd-uki-tools")
    (version (pin "systemd" "version"))
    (source (pinned-git-origin "systemd" "https://github.com/systemd/systemd"))
    (build-system meson-build-system)
    (arguments
     (list
      #:configure-flags
      #~(list "-Dmode=release"
              "-Dauto_features=disabled"
              "-Dbootloader=enabled"
              "-Dukify=enabled"
              "-Dtpm=false"
              "-Dtests=false"
              ;; Without Secure Boot or shim, the stub needs no distribution
              ;; SBAT entry.
              "-Dsbat-distro=")
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda _
              (invoke "ninja" "src/boot/linuxx64.efi.stub" "ukify")))
          (replace 'install
            (lambda _
              (let ((ukify (string-append #$output "/bin/ukify")))
                (install-file "src/boot/linuxx64.efi.stub"
                              (string-append #$output "/lib/systemd/boot/efi"))
                (install-file "ukify" (dirname ukify))
                (chmod ukify #o555)
                (wrap-program ukify
                  `("GUIX_PYTHONPATH" ":" prefix
                    (,(getenv "GUIX_PYTHONPATH"))))))))))
    (native-inputs
     (map specification->package
          '("gperf"
            "pkg-config"
            "python"
            "python-jinja2"
            "python-pefile"
            "python-pyelftools")))
    (home-page "https://systemd.io")
    (synopsis "systemd ukify and EFI stub")
    (description "The systemd @command{ukify} tool and the EFI stub it uses to
build unified kernel images.")
    (license license:lgpl2.1+)))

(define stogas-ovmf
  (package
    (inherit ovmf-x86-64)
    (name "stogas-ovmf")
    (version (pin "edk2" "version"))
    (source
     (pinned-git-origin "edk2" "https://github.com/tianocore/edk2"
                        #:recursive? #t
                        #:patches
                        (list (patch-file "edk2-amdsev-kernel-only.patch"))))
    (arguments
     (substitute-keyword-arguments (package-arguments ovmf-x86-64)
       ((#:phases phases)
        #~(modify-phases #$phases
            (replace 'build
              (lambda _
                (invoke "build" "-a" "X64" "-t" "GCC"
                        "-p" "OvmfPkg/AmdSev/AmdSevX64.dsc")))
            (delete 'install-efi-shell)
            (replace 'install
              (lambda _
                (install-file "Build/AmdSev/RELEASE_GCC/FV/OVMF.fd"
                              (string-append #$output "/share/firmware"))))
            (delete 'install-qemu-firmware-metadata)))))
    (synopsis "AmdSev OVMF firmware that boots only the measured kernel")
    (description "OVMF built from @file{OvmfPkg/AmdSev/AmdSevX64.dsc}.  It
boots the unified kernel image from the IGVM file and halts if that fails.")))

;;; Rust tools build offline from the crates their reviewed Cargo.lock names.

(define %crates-io "registry+https://github.com/rust-lang/crates.io-index")

(define (cargo-lock-packages lock)
  "Return the fields of each package in the Cargo.lock file LOCK that comes
from a registry or Git rather than the workspace."
  (call-with-input-file lock
    (lambda (port)
      (let loop ((packages '()) (fields #f))
        (let ((line (read-line port))
              (done (if fields (cons fields packages) packages)))
          (cond
           ((eof-object? line)
            (filter (lambda (fields) (assoc-ref fields "source"))
                    (reverse done)))
           ((string=? line "[[package]]")
            (loop done '()))
           ((and fields
                 (string-match "^(name|version|source|checksum) = \"([^\"]*)\"$"
                               line))
            => (lambda (m)
                 (loop packages
                       (acons (match:substring m 1) (match:substring m 2)
                              fields))))
           (else
            (loop packages fields))))))))

(define (cargo-git-source fields)
  "Return the URL, revision and commit of a Git package, or #f."
  (match (string-match "^git\\+([^?#]+)\\?rev=([^#]+)#([0-9a-f]{40})$"
                       (assoc-ref fields "source"))
    (#f #f)
    (m (map (lambda (group) (match:substring m group)) '(1 2 3)))))

(define (cargo-crate fields)
  "Return the vendor directory, source and checksum of one locked package."
  (let ((name (assoc-ref fields "name"))
        (version (assoc-ref fields "version"))
        (source (assoc-ref fields "source"))
        (checksum (assoc-ref fields "checksum")))
    (list
     (string-append name "-" version)
     (match (cargo-git-source fields)
       ((url _ commit)
        (unless (string=? commit (pin name "commit"))
          (error "Git crate differs from its release pin" name commit))
        (pinned-git-origin name url #:version version))
       (#f
        (unless (and (string=? source %crates-io) checksum)
          (error "unsupported Cargo source" name source))
        (origin
          (method url-fetch)
          (uri (crate-uri name version))
          (file-name (string-append (crate-name->package-name name)
                                    "-" version ".tar.gz"))
          (sha256 (base16-string->bytevector checksum)))))
     checksum)))

(define (cargo-config packages)
  (string-append
   "[source.crates-io]\nreplace-with = \"vendored-sources\"\n"
   (string-concatenate
    (filter-map
     (lambda (fields)
       (match (cargo-git-source fields)
         ((url rev _)
          (format #f "[source.~s]\ngit = ~s\nrev = ~s\nreplace-with = \"vendored-sources\"\n"
                  (assoc-ref fields "name") url rev))
         (#f #f)))
     packages))
   "[source.vendored-sources]\ndirectory = \"vendor\"\n"))

(define* (cargo-package name version source lock build check outputs
                        home-page synopsis license
                        #:key (directory ".") (target "target/release")
                        (install-directory "bin"))
  "Build SOURCE with the crates in the Cargo.lock file LOCK and install the
OUTPUTS files that BUILD leaves in TARGET."
  (let ((packages (cargo-lock-packages lock))
        (lock-file (local-file lock)))
    (package
      (name name)
      (version version)
      (source source)
      (build-system gnu-build-system)
      (arguments
       (list
        #:modules '((guix build gnu-build-system)
                    (guix build utils)
                    (ice-9 match))
        #:phases
        #~(modify-phases %standard-phases
            (delete 'bootstrap)
            (delete 'configure)
            (delete 'patch-usr-bin-file)
            (delete 'patch-source-shebangs)
            (delete 'patch-generated-file-shebangs)
            (add-after 'unpack 'vendor-crates
              (lambda _
                (chdir #$directory)
                ;; A lock in the source must match the reviewed copy.
                (if (file-exists? "Cargo.lock")
                    (invoke "cmp" "Cargo.lock" #$lock-file)
                    (copy-file #$lock-file "Cargo.lock"))
                (for-each
                 (match-lambda
                   ((name crate checksum)
                    (let ((target (string-append "vendor/" name)))
                      (if checksum
                          (begin
                            (mkdir-p target)
                            (invoke "tar" "-xzf" crate "-C" target
                                    "--strip-components=1"))
                          (copy-recursively crate target
                                            #:log (%make-void-port "w")))
                      (call-with-output-file
                          (string-append target "/.cargo-checksum.json")
                        (lambda (port)
                          (format port "{\"files\":{},\"package\":~a}"
                                  (if checksum
                                      (string-append "\"" checksum "\"")
                                      "null")))))))
                 '#$(map cargo-crate packages))
                (mkdir-p ".cargo")
                (call-with-output-file ".cargo/config.toml"
                  (lambda (port)
                    (display #$(cargo-config packages) port)))
                (setenv "CARGO_HOME" (string-append (getcwd) "/.cargo"))
                (setenv "CC" "gcc")))
            (replace 'build
              (lambda _ #$build))
            (replace 'check
              (lambda* (#:key tests? #:allow-other-keys)
                (when tests? #$check)))
            (replace 'install
              (lambda _
                (for-each
                 (lambda (file)
                   (install-file (string-append #$target "/" file)
                                 (string-append #$output "/"
                                                #$install-directory)))
                 '#$outputs))))))
      ;; This Rust ships without rustdoc, so tests skip doctests.
      (native-inputs (list rust-1.95 (list rust-1.95 "cargo")))
      (home-page home-page)
      (synopsis synopsis)
      (description synopsis)
      (license license))))

(define stogas-virt-firmware-rs
  (cargo-package
   "stogas-virt-firmware-rs" (pin "virtFirmwareRs" "version")
   (pinned-git-origin "virtFirmwareRs" "https://gitlab.com/kraxel/virt-firmware-rs"
                      #:name "virt-firmware-rs"
                      #:patches (list (patch-file "virt-firmware-rs-qemu-kvm.patch")))
   (release-path "locks/virt-firmware-rs.Cargo.lock")
   #~(invoke "cargo" "build" "--release" "--locked" "--offline"
             "-p" "virtfw-igvm-tools" "--bins")
   #~(invoke "cargo" "test" "--release" "--locked" "--offline" "--tests"
             "-p" "virtfw-igvm-tools")
   '("igvm-inspect" "igvm-update" "igvm-wrap")
   "https://gitlab.com/kraxel/virt-firmware-rs"
   "virt-firmware-rs IGVM tools with four-CPU SEV-SNP support"
   license:expat))

(define stogas-igvmmeasure
  (cargo-package
   "stogas-igvmmeasure" (pin "svsm" "version")
   (pinned-git-origin "svsm" "https://github.com/coconut-svsm/svsm"
                      #:patches (list (patch-file "svsm-igvmmeasure-qemu-kvm.patch")))
   (release-path "locks/igvmmeasure.Cargo.lock")
   #~(invoke "cargo" "build" "--release" "--locked" "--offline")
   #~(invoke "cargo" "test" "--release" "--locked" "--offline" "--tests")
   '("igvmmeasure")
   "https://github.com/coconut-svsm/svsm"
   "COCONUT-SVSM igvmmeasure tool that checks QEMU/KVM SEV-SNP launches"
   license:expat
   #:directory "tools/igvmmeasure"))

(define stogas-ntpd-rs
  (cargo-package
   "stogas-ntpd-rs" (pin "ntpdRs" "version")
   (pinned-git-origin "ntpdRs" "https://github.com/pendulum-project/ntpd-rs"
                      #:name "ntpd-rs"
                      #:patches (list (patch-file "ntpd-rs-dependency-updates.patch")))
   (release-path "locks/ntpd-rs.Cargo.lock")
   ;; The guest rootfs holds only static binaries. An explicit target keeps
   ;; crt-static off build scripts and procedural macros. Guix glibc cannot
   ;; relocate a static PIE at startup, so the daemon is a fixed-address
   ;; static executable like the gateway. The client needs neither the NTS
   ;; server nor PPS support.
   #~(begin
       (setenv "CARGO_BUILD_TARGET" "x86_64-unknown-linux-gnu")
       (setenv "CARGO_PROFILE_RELEASE_DEBUG" "false")
       (setenv "RUSTFLAGS" "-C target-feature=+crt-static -C relocation-model=static")
       (setenv "NTPD_RS_GIT_REV" #$(pin "ntpdRs" "commit"))
       (setenv "NTPD_RS_GIT_DATE" #$(pin "ntpdRs" "commitDate"))
       (invoke "cargo" "build" "--release" "--locked" "--offline"
               "-p" "ntpd" "--bin" "ntp-daemon"
               "--no-default-features" "--features" "aws-lc,rustcrypto"))
   ;; The libraries hold the protocol and daemon logic; the integration
   ;; tests cover only the unshipped ntp-ctl. Without nsswitch.conf, glibc
   ;; in the build sandbox stops after the failed DNS lookup and never
   ;; reads /etc/hosts for localhost.
   #~(invoke "cargo" "test" "--release" "--locked" "--offline" "--lib"
             "-p" "ntp-proto" "-p" "ntpd"
             "--no-default-features" "--features" "aws-lc,rustcrypto"
             "--" "--skip" "allow_srv_direct_name_resolution")
   '("ntp-daemon")
   "https://github.com/pendulum-project/ntpd-rs"
   "Static ntpd-rs NTS client daemon"
   (list license:asl2.0 license:expat)
   #:target "target/x86_64-unknown-linux-gnu/release"))

;; A staging build sets STOGAS_VERIFIER_SOURCE to a captured working tree.
(define %verifier-snapshot
  (let ((source (getenv "STOGAS_VERIFIER_SOURCE")))
    (and source (not (string-null? source)) source)))

(define stogas-verifier
  (cargo-package
   "stogas-ffi" "0"
   (if %verifier-snapshot
       (local-file %verifier-snapshot "stogas-verifier-source" #:recursive? #t)
       (pinned-git-origin "stogasVerifier" "https://github.com/StogasAI/stogas"
                          #:name "stogas-verifier" #:version "0"))
   (if %verifier-snapshot
       (string-append %verifier-snapshot "/Cargo.lock")
       (release-path "locks/stogas-verifier.Cargo.lock"))
   #~(invoke "cargo" "build" "--release" "--locked" "--offline"
             "-p" "stogas-ffi"
             "--no-default-features" "--features" "staging,gateway")
   #~(invoke "cargo" "test" "--release" "--locked" "--offline" "--tests"
             "-p" "stogas-core" "-p" "stogas-ffi"
             "--no-default-features"
             "--features" "staging,stogas-ffi/gateway")
   '("libstogas_ffi.a")
   "https://github.com/StogasAI/stogas"
   "Offline Stogas evidence verifier library for the gateway"
   license:asl2.0
   #:install-directory "lib"))
