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

(define %linux-6-18
  (specification->package "linux-libre@6.18.35"))

(define stogas-linux-6-18
  (package
    (inherit %linux-6-18)
    (name "stogas-linux-6.18")
    (version "6.18.35")
    (arguments
     (substitute-keyword-arguments (package-arguments %linux-6-18)
       ((#:phases phases)
        #~(modify-phases #$phases
            (add-after 'configure 'stogas-built-in-guest-drivers
              (lambda _
                (let ((disabled '("DEBUG_INFO"
                                  "DEBUG_INFO_BTF"
                                  "DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT"
                                  "DEBUG_INFO_REDUCED"
                                  "DEBUG_INFO_SPLIT"
                                  "FTRACE"
                                  "KALLSYMS"
                                  "KPROBES"
                                  "MODULES"))
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
                                   "INET"
                                   "IPV6"
                                   "IP_PNP"
                                   "IP_PNP_DHCP"
                                   "NETDEVICES"
                                   "NET"
                                   "PACKET"
                                   "PCI"
                                   "PCI_DIRECT"
                                   "PCI_MSI"
                                   "PCI_MMCONFIG"
                                   "PROC_FS"
                                   "RD_ZSTD"
                                   "SECURITYFS"
                                   "SERIAL_8250"
                                   "SERIAL_8250_CONSOLE"
                                   "SERIAL_8250_PCI"
                                   "SEV_GUEST"
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
                                   "VIRTIO_PCI_LEGACY"
                                   "VIRTIO_VSOCKETS"
                                   "VIRTIO_VSOCKETS_COMMON"
                                   "VSOCKETS")))
                  (setenv "ARCH" "x86_64")
                  (invoke "make" "ARCH=x86_64" "allnoconfig")
                  (for-each
                   (lambda (option)
                     (invoke "scripts/config" "--disable" option))
                   disabled)
                  (for-each
                   (lambda (option)
                     (invoke "scripts/config" "--enable" option))
                   built-ins)
                  (invoke "make" "ARCH=x86_64" "olddefconfig")
                  (for-each
                   (lambda (option)
                     (invoke "grep" "-q"
                             (string-append "^CONFIG_" option "=y$")
                             ".config"))
                   built-ins)
                  (invoke "grep" "-q" "^# CONFIG_MODULES is not set$"
                          ".config"))))))))
    (synopsis "Stogas SEV-SNP guest Linux kernel")
    (description
     "Linux 6.18.35 with the virtio, EFI secret, configfs/TSM, and SEV-SNP
guest-report paths built into the kernel for a diskless Go initramfs.")
    (home-page "https://stogas.ai")
    (license (package-license %linux-6-18))))

(define stogas-systemd-uki-tools
  (package
    (name "stogas-systemd-uki-tools")
    (version "260")
    (source
     (origin
       (method url-fetch)
       (uri "https://github.com/systemd/systemd/archive/55393e3cecf6f2b274c379c39d2375a136474e8e.tar.gz")
       (sha256
        (base32 "1f1vk0x2a3q6ilbw8sgvdz40vgz050b9c6k6xq5zpq0j23pvqf7w"))))
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
    (description "Deterministic systemd v260 ukify and linuxx64.efi.stub.")
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

(define (rust-tool-package name version source vendor cargo-config lock build-command
                           binaries synopsis)
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
          (add-after 'unpack 'attach-vendored-dependencies
            (lambda _
              (copy-file #$lock "Cargo.lock")
              (mkdir-p ".cargo")
              (copy-recursively #$cargo-config ".cargo")
              (copy-recursively #$vendor "vendor")))
          (add-after 'attach-vendored-dependencies 'stogas-kvm-vmsa-last
            (lambda _
              (let ((builder "igvm-tools/src/builder.rs"))
                (when (file-exists? builder)
                  (substitute* builder
                    (("directives\\.sort_by\\(Self::sort_pages\\);")
                     "directives.sort_by(|a, b| {
            let a_is_vmsa = matches!(a, IgvmDirectiveHeader::SnpVpContext { .. });
            let b_is_vmsa = matches!(b, IgvmDirectiveHeader::SnpVpContext { .. });
            match (a_is_vmsa, b_is_vmsa) {
                (false, true) => Ordering::Less,
                (true, false) => Ordering::Greater,
                _ => Self::sort_pages(a, b),
            }
        });"))))))
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
    (native-inputs (map pkg '("rust")))
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
      (base32 "09gahq7j8s2grlmgjd5nnv2gvway2gv52p5b8wqlywjj175l5lph")))
   (release-file "vendor/virt-firmware-rs/vendor"
                 "virt-firmware-rs-vendor"
                 #:recursive? #t)
   (release-file "vendor/virt-firmware-rs/.cargo"
                 "virt-firmware-rs-cargo-config"
                 #:recursive? #t)
   (release-file "vendor/virt-firmware-rs/Cargo.lock"
                 "virt-firmware-rs-Cargo.lock")
   #~(invoke "cargo" "build" "--release" "--locked" "--offline"
             "-p" "virtfw-igvm-tools" "--bins")
   '("igvm-wrap" "igvm-update")
   "Pinned virt-firmware-rs IGVM update tools"))

(define stogas-igvmmeasure
  (rust-tool-package
   "stogas-igvmmeasure"
   "2026.05"
   (release-file "vendor/igvmmeasure/source"
                 "igvmmeasure-source"
                 #:recursive? #t)
   (release-file "vendor/igvmmeasure/vendor"
                 "igvmmeasure-vendor"
                 #:recursive? #t)
   (release-file "vendor/igvmmeasure/.cargo"
                 "igvmmeasure-cargo-config"
                 #:recursive? #t)
   (release-file "vendor/igvmmeasure/Cargo.lock"
                 "igvmmeasure-Cargo.lock")
   #~(invoke "cargo" "build" "--release" "--locked" "--offline")
   '("igvmmeasure")
   "Pinned standalone SVSM igvmmeasure tool"))
