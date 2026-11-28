;; The build fetches this repository with Git and names its copy in
;; STOGAS_GUIX_CHANNEL (scripts/guix.sh).  Guix authenticates the commit from
;; the introduction wherever it reads it.  ci.guix.gnu.org built Guix itself
;; at this commit (https://ci.guix.gnu.org/jobset/guix), so the build
;; downloads it instead of compiling it.
(list
 (channel
  (name 'guix)
  (url (or (getenv "STOGAS_GUIX_CHANNEL") "https://git.guix.gnu.org/guix.git"))
  (commit "9d3015be4533203f75d9d173a1c4f7f157be664e")
  (introduction
   (make-channel-introduction
    "9edb3f66fd807b096b48283debdcddccfea34bad"
    (openpgp-fingerprint
     "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA")))))
