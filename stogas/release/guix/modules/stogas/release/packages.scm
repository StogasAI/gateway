(define-module (stogas release packages)
  #:use-module (gnu packages)
  #:use-module (gnu packages firmware)
  #:use-module (guix base32)
  #:use-module (guix build-system gnu)
  #:use-module (guix build-system meson)
  #:use-module (guix download)
  #:use-module (guix gexp)
  #:use-module (guix git-download)
  #:use-module (guix packages)
  #:use-module (guix utils)
  #:use-module (ice-9 match)
  #:export (pkg
            stogas-edk2-amdsev-ovmf
            stogas-go-1-26
            stogas-igvmmeasure
            stogas-linux-6-18
            stogas-systemd-uki-tools
            stogas-virt-firmware-rs-tools
            stogas-release-root))

(define %this-file
  (or (current-filename)
      (and=> (getenv "STOGAS_RELEASE_ROOT")
             (lambda (root)
               (string-append root
                              "/guix/modules/stogas/release/packages.scm")))))

(define stogas-release-root
  (dirname (dirname (dirname (dirname (dirname %this-file))))))

(define (pkg spec)
  (specification->package spec))

(define* (release-file path name #:key recursive?)
  (local-file (string-append stogas-release-root "/" path)
              name
              #:recursive? (or recursive? #f)))

(define (patch-file path)
  (release-file (string-append "patches/" path) path))

(define %linux-6-18
  (specification->package "linux-libre@6.18.38"))

(define %go-1-26
  (specification->package "go@1.26.4"))

(define stogas-go-1-26
  (package
    (inherit %go-1-26)
    (name "stogas-go")
    (version "1.26.5")
    (source
     (origin
       (method url-fetch)
       (uri "https://go.dev/dl/go1.26.5.src.tar.gz")
       (sha256
        (base32 "0hnwn9v6kk2cfqgd8jbv7p9nd16rmcb42nrf75kwashphyyf8ns9"))))))

(define stogas-linux-6-18
  (package
    (inherit %linux-6-18)
    (name "stogas-linux-6.18")
    (version "6.18.38")
    (arguments
     (substitute-keyword-arguments (package-arguments %linux-6-18)
       ((#:phases phases)
        #~(modify-phases #$phases
            (add-after 'configure 'stogas-built-in-guest-drivers
              (lambda _
	                (let ((disabled '("DEBUG_INFO"
	                                  "BINFMT_MISC"
	                                  "BPF_SYSCALL"
	                                  "DEBUG_INFO_BTF"
	                                  "DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT"
	                                  "DEBUG_INFO_REDUCED"
	                                  "DEBUG_INFO_SPLIT"
	                                  "FW_LOADER"
	                                  "FTRACE"
	                                  "HIBERNATION"
	                                  "KALLSYMS"
	                                  "KEXEC"
	                                  "KPROBES"
	                                  "MODULES"
	                                  "PACKET"
	                                  "PROFILING"
	                                  "USER_NS"
	                                  "VIRTIO_PCI_LEGACY"))
	                      (built-ins '("ACPI"
	                                   "AMD_MEM_ENCRYPT"
	                                   "BINFMT_ELF"
	                                   "BLK_DEV_INITRD"
	                                   "CONFIGFS_FS"
	                                   "CPU_SUP_AMD"
	                                   "DEVTMPFS"
	                                   "DEVTMPFS_MOUNT"
	                                   "DMI"
	                                   "EARLY_PRINTK"
	                                   "EFI"
	                                   "EFI_COCO_SECRET"
	                                   "EFI_SECRET"
	                                   "EFI_STUB"
	                                   "ELF_CORE"
	                                   "EXPERT"
	                                   "FORTIFY_SOURCE"
	                                   "FW_CFG_SYSFS"
	                                   "HARDENED_USERCOPY"
	                                   "INET"
	                                   "INIT_ON_ALLOC_DEFAULT_ON"
	                                   "IPV6"
	                                   "IP_PNP"
	                                   "IP_PNP_DHCP"
	                                   "NETDEVICES"
	                                   "NET"
	                                   "PCI"
	                                   "PCI_DIRECT"
	                                   "PCI_MSI"
	                                   "PCI_MMCONFIG"
	                                   "PROC_FS"
	                                   "RANDOMIZE_BASE"
	                                   "RD_ZSTD"
	                                   "SECCOMP"
	                                   "SECCOMP_FILTER"
	                                   "SECURITYFS"
	                                   "SERIAL_8250"
	                                   "SERIAL_8250_CONSOLE"
	                                   "SERIAL_8250_PCI"
	                                   "SEV_GUEST"
	                                   "SLAB_FREELIST_HARDENED"
	                                   "SLAB_FREELIST_RANDOM"
	                                   "SMP"
	                                   "STACKPROTECTOR"
	                                   "STACKPROTECTOR_STRONG"
	                                   "STRICT_KERNEL_RWX"
	                                   "SYSFS"
	                                   "TMPFS"
	                                   "TTY"
	                                   "TSM_GUEST"
                                   "TSM_REPORTS"
                                   "UNIX"
	                                   "VIRT_DRIVERS"
	                                   "VIRTIO_MENU"
	                                   "VIRTIO"
	                                   "VIRTIO_CONSOLE"
	                                   "VIRTIO_NET"
	                                   "VIRTIO_PCI"
	                                   "VIRTIO_VSOCKETS"
	                                   "VIRTIO_VSOCKETS_COMMON"
	                                   "VSOCKETS")))
                  (setenv "ARCH" "x86_64")
                  (setenv "KBUILD_BUILD_TIMESTAMP" "1970-01-01 00:00:01 UTC")
                  (unsetenv "KCONFIG_ALLCONFIG")
                  (invoke "make" "ARCH=x86_64" "allnoconfig")
                  (for-each
                   (lambda (option)
                     (invoke "scripts/config" "--disable" option))
                   disabled)
                  (for-each
                   (lambda (option)
                     (invoke "scripts/config" "--enable" option))
                   built-ins)
                  (invoke "scripts/config" "--set-val" "NR_CPUS" "4")
                  (invoke "make" "ARCH=x86_64" "olddefconfig")
                  (define (assert-enabled option)
                    (invoke "grep" "-q"
                            (string-append "^CONFIG_" option "=y$")
                            ".config"))
                  (define (assert-disabled option)
                    (invoke "bash" "-c"
                            (string-append
                             "! grep -q '^CONFIG_" option "=' .config"
                             " || grep -q '^# CONFIG_" option " is not set$' .config")))
                  (for-each assert-enabled built-ins)
	                  (invoke "grep" "-q" "^# CONFIG_MODULES is not set$"
	                          ".config")
                  (invoke "grep" "-q" "^CONFIG_NR_CPUS=4$" ".config")
	                  (for-each assert-disabled disabled))))))))
    (synopsis "Stogas SEV-SNP guest Linux kernel")
    (description
     "Linux 6.18.38 with the virtio, EFI secret, configfs/TSM, and SEV-SNP
guest-report paths built into the kernel for a diskless Go initramfs.")
    (home-page "https://stogas.ai")
    (license (package-license %linux-6-18))))

(define stogas-systemd-uki-tools
  (package
    (name "stogas-systemd-uki-tools")
    (version "261")
    (source
     (origin
       (method url-fetch)
       (uri "https://github.com/systemd/systemd/archive/de9dbc37ad4aa637e200ac02a0545095997055df.tar.gz")
       (sha256
         (base32 "0lidwd6k6agrn1nh72vv3g7y5sca2j0dmzf7n7rpwsnyvfancn1j"))))
    (build-system meson-build-system)
    (arguments
     (list
      #:configure-flags
      #~(list "-Dmode=release"
              "-Dauto_features=disabled"
              "-Dbootloader=enabled"
              "-Defi=true"
              "-Dukify=enabled"
              "-Dtpm=false"
              "-Dtests=false"
              "-Dinstall-tests=false"
              "-Dsbat-distro=stogas"
              "-Dsbat-distro-summary=Stogas"
              "-Dsbat-distro-url=https://stogas.ai/security"
              "-Dsbat-distro-pkgname=stogas-gateway"
              "-Dsbat-distro-version=1")
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (replace 'build
            (lambda _
              (invoke "ninja"
                      "src/boot/linuxx64.efi.stub"
                      "ukify")))
          (replace 'install
            (lambda _
              (let ((bin (string-append #$output "/bin"))
                    (stub-dir (string-append #$output
                                             "/lib/systemd/boot/efi")))
                (mkdir-p bin)
                (mkdir-p stub-dir)
                (copy-file "ukify" (string-append bin "/ukify"))
                (chmod (string-append bin "/ukify") #o555)
                (wrap-program (string-append bin "/ukify")
                  `("GUIX_PYTHONPATH" ":" prefix
                    (,(getenv "GUIX_PYTHONPATH"))))
                (copy-file "src/boot/linuxx64.efi.stub"
                           (string-append stub-dir "/linuxx64.efi.stub"))))))))
    (native-inputs
     (map pkg
          '("bash-minimal"
            "binutils"
            "coreutils"
            "gcc-toolchain"
            "gperf"
            "meson"
            "ninja"
            "pkg-config"
            "python"
            "python-jinja2"
            "python-pefile"
            "python-pyelftools")))
    (synopsis "Pinned systemd ukify and EFI stub")
    (description "Deterministic systemd v261 ukify and linuxx64.efi.stub.")
    (home-page "https://systemd.io")
    (license #f)))

(define stogas-edk2-amdsev-ovmf
  (package
    (inherit ovmf-x86-64)
    (name "stogas-edk2-amdsev-ovmf")
    (version "stable202605")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/tianocore/edk2")
             (commit "b03a21a63e3bd001f52c527e5a57feddb53a690b")
             (recursive? #t)))
       (file-name (git-file-name "edk2" version))
       (sha256
        (base32 "0mpfs9vd9fy6103k83jwd58xcy1j908m6b27bclxmbrc9vim9l8n"))))
    (arguments
     (substitute-keyword-arguments (package-arguments ovmf-x86-64)
       ((#:phases phases)
        #~(modify-phases #$phases
            (add-before 'build 'pin-amdsev-grub-tools
              (lambda _
                (invoke "sed" "-i"
                        "s|mkfs\\.msdos -C --|mkfs.msdos --invariant -C --|"
                        "OvmfPkg/AmdSev/Grub/grub.sh")
                (invoke "sed" "-i"
                        "s|mcopy -i |mcopy -m -i |"
                        "OvmfPkg/AmdSev/Grub/grub.sh")
                (invoke "sed" "-i"
                        "s|(UINT32) time(NULL)|(UINT32) 1|g"
                        "BaseTools/Source/C/GenFw/Elf32Convert.c"
                        "BaseTools/Source/C/GenFw/Elf64Convert.c")
                (invoke "sed" "-i"
                        (string-append "s|^mkimage=$|mkimage="
                                       #$(file-append (pkg "grub-efi")
                                                      "/bin/grub-mkimage")
                                       "|")
                        "OvmfPkg/AmdSev/Grub/grub.sh")
                (invoke "sed" "-i"
                        (string-append "s|mkfs\\.msdos|"
                                       #$(file-append (pkg "dosfstools")
                                                      "/sbin/mkfs.fat")
                                       "|g")
                        "OvmfPkg/AmdSev/Grub/grub.sh")
                (invoke "sed" "-i"
                        (string-append "s|\\bmcopy\\b|"
                                       #$(file-append (pkg "mtools")
                                                      "/bin/mcopy")
                                       "|g")
                        "OvmfPkg/AmdSev/Grub/grub.sh")
                (invoke "sed" "-i"
                        "/linuxefi/d;/sevsecret/d"
                        "OvmfPkg/AmdSev/Grub/grub.sh"
                        "OvmfPkg/AmdSev/Grub/grub.cfg")
                (invoke "touch" "-d" "1980-01-01 00:00:00 UTC"
                        "OvmfPkg/AmdSev/Grub/grub.cfg")
                (invoke "grep" "-q"
                        #$(file-append (pkg "grub-efi") "/bin/grub-mkimage")
                        "OvmfPkg/AmdSev/Grub/grub.sh")))
            (replace 'build
              (lambda _
                (invoke "build"
                        "-a" "X64"
                        "-t" "GCC"
                        "-p" "OvmfPkg/AmdSev/AmdSevX64.dsc")))
            (replace 'install
              (lambda _
                (let* ((firmware-dir (string-append #$output
                                                     "/share/firmware"))
                       (files (sort (find-files "Build" "^OVMF\\.fd$")
                                    string<?)))
                  (when (null? files)
                    (error "AmdSev OVMF.fd was not produced"))
                  (mkdir-p firmware-dir)
                  (copy-file (car files)
                             (string-append firmware-dir
                                            "/ovmf-amdsev-x64.fd")))))))))
    (synopsis "Pinned edk2 AmdSev OVMF firmware")
    (description "edk2 stable202605 OVMF built from OvmfPkg/AmdSev/AmdSevX64.dsc.")
    (home-page "https://github.com/tianocore/edk2")
    (native-inputs
     (modify-inputs (package-native-inputs ovmf-x86-64)
       (append (pkg "dosfstools")
               (pkg "grub-efi")
               (pkg "mtools"))))))

(define (rust-tool-package name version source source-directory vendor lock
                           vendor-sha256 config-body build-command binaries
                           synopsis)
  (package
    (name name)
    (version version)
    (source source)
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (delete 'patch-usr-bin-file)
          (delete 'patch-source-shebangs)
          (delete 'patch-generated-file-shebangs)
          (add-after 'unpack 'detach-source-directory
            (lambda _
              (use-modules (ice-9 ftw))
              (unless (string=? #$source-directory ".")
                (let ((root (getcwd))
                      (detached (string-append (getcwd)
                                               "/../stogas-rust-tool-source")))
                  (copy-recursively #$source-directory detached)
                  (for-each
                   (lambda (entry)
                     (unless (member entry '("." ".."))
                       (let ((path (string-append root "/" entry)))
                         (if (file-is-directory? path)
                             (delete-file-recursively path)
                             (delete-file path)))))
                   (scandir root))
                  (for-each
                   (lambda (entry)
                     (unless (member entry '("." ".."))
                       (let ((source (string-append detached "/" entry))
                             (target (string-append root "/" entry)))
                         (if (file-is-directory? source)
                             (copy-recursively source target)
                             (copy-file source target)))))
                   (scandir detached))
                  (delete-file-recursively detached)))))
          (add-after 'detach-source-directory 'attach-vendored-dependencies
            (lambda _
              (copy-file #$lock "Cargo.lock")
              (mkdir-p ".cargo")
              (call-with-output-file ".cargo/config.toml"
                (lambda (port)
                  (display #$config-body port)))
              (copy-recursively #$vendor "vendor")))
          (add-after 'attach-vendored-dependencies 'verify-vendored-dependencies
            (lambda _
              (use-modules (ice-9 rdelim))
              (invoke "bash" "-c"
                      (string-append
                       "cd vendor && find . -type f -print0 | LC_ALL=C sort -z"
                       " | xargs -0 sha256sum | sha256sum"
                       " | cut -d' ' -f1 > ../.vendor.sha256"))
              (let ((actual (call-with-input-file ".vendor.sha256" read-line)))
                (unless (string=? actual #$vendor-sha256)
                  (error "Cargo vendor cache hash mismatch" actual #$vendor-sha256)))))
          (replace 'build
            (lambda _
              (setenv "CARGO_NET_OFFLINE" "true")
              (setenv "HOME" (getcwd))
              #$build-command))
          (replace 'install
            (lambda _
              (let ((bin (string-append #$output "/bin")))
                (mkdir-p bin)
                (for-each
                 (lambda (binary)
                   (install-file (string-append "target/release/" binary)
                                 bin))
                 '#$binaries)))))))
    (native-inputs (map pkg '("bash-minimal" "coreutils" "findutils" "rust")))
    (synopsis synopsis)
    (description synopsis)
    (home-page "https://stogas.ai")
    (license #f)))

(define stogas-virt-firmware-rs-tools
  (rust-tool-package
   "stogas-virt-firmware-rs-tools"
   "26.4"
   (origin
     (method url-fetch)
     (uri "https://gitlab.com/kraxel/virt-firmware-rs/-/archive/e01dffc463934547a42506df656becd9061926f7/virt-firmware-rs-e01dffc463934547a42506df656becd9061926f7.tar.gz")
     (sha256
      (base32 "09gahq7j8s2grlmgjd5nnv2gvway2gv52p5b8wqlywjj175l5lph"))
     (patches
      (list (patch-file "virt-firmware-rs-kvm-vmsa-last.patch")
            (patch-file "virt-firmware-rs-kvm-real-mode-cr0-ne.patch")
            (patch-file "virt-firmware-rs-snp-cpu-count.patch"))))
   "."
   (release-file "vendor/virt-firmware-rs/vendor"
                 "virt-firmware-rs-vendor"
                 #:recursive? #t)
   (release-file "locks/virt-firmware-rs.Cargo.lock"
                 "virt-firmware-rs-Cargo.lock")
   "f255fd2e4b39db99e7c8127d4bcac6b0f06565aa2bd2f1c59669cee8280dd3a5"
   "[source.crates-io]
replace-with = \"vendored-sources\"

[source.\"git+https://github.com/ardbiesheuvel/efiloader.git?rev=699b3142085c\"]
git = \"https://github.com/ardbiesheuvel/efiloader.git\"
rev = \"699b3142085c\"
replace-with = \"vendored-sources\"

[source.vendored-sources]
directory = \"vendor\"
"
   #~(invoke "cargo" "build" "--release" "--locked" "--offline"
             "-p" "virtfw-igvm-tools" "--bins")
   '("igvm-wrap" "igvm-update")
   "Pinned virt-firmware-rs IGVM update tools"))

(define stogas-igvmmeasure
  (rust-tool-package
   "stogas-igvmmeasure"
   "2026.05"
   (origin
     (method url-fetch)
     (uri "https://github.com/coconut-svsm/svsm/archive/8850f7bd766e0b592d01efb67c615a9d8f171269.tar.gz")
     (sha256
      (base32 "03lnkgbw40p43dx2pf07kdjayxz4mv1hy752dk7h27awc680y7ih"))
     (patches
      (list (patch-file "svsm-igvmmeasure-standalone-cargo.patch")
            (patch-file "svsm-igvmmeasure-kvm-vmsa-normalization.patch"))))
   "tools/igvmmeasure"
   (release-file "vendor/igvmmeasure/vendor"
                 "igvmmeasure-vendor"
                 #:recursive? #t)
   (release-file "locks/igvmmeasure.Cargo.lock"
                 "igvmmeasure-Cargo.lock")
   "a8e661722a66994ceee5fb73be70acbefcfec0524e81e1c37dc3612527c8618d"
   "[source.crates-io]
replace-with = \"vendored-sources\"

[source.vendored-sources]
directory = \"vendor\"
"
   #~(invoke "cargo" "build" "--release" "--locked" "--offline")
   '("igvmmeasure")
   "Pinned standalone SVSM igvmmeasure tool"))
