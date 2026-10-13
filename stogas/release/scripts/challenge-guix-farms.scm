;; Compare the local copy of every Guix package used to build a store item
;; with the copies that the two Guix build farms publish, which each farm
;; builds from source on its own.  Exits with status 1 when a local copy
;; matches neither farm or when no farm answers, and stops when a farm's
;; published hash is not signed with that farm's key.
;;
;; Usage: guix repl -- challenge-guix-farms.scm /gnu/store/...-release

(use-modules (guix store)
             (guix derivations)
             (guix narinfo)
             (guix substitutes)
             (guix pki)
             (gcrypt pk-crypto)
             (rnrs bytevectors)
             (srfi srfi-1)
             (srfi srfi-26)
             (ice-9 format)
             (ice-9 match))

(define farms
  ;; Each farm's signing key, as Guix ships it in etc/substitutes.
  '(("ci.guix.gnu.org"
     "(public-key (ecc (curve Ed25519) (q #8D156F295D24B0D9A86FA5741A840FF2D24F60F7B6C4134814AD55625971B394#)))")
    ("bordeaux.guix.gnu.org"
     "(public-key (ecc (curve Ed25519) (q #7D602902D3A2DBB83F8A0FB98602A754C5493B0B778C8D1DD4E0F41DE14DE34F#)))")))

(define (build-closure store item)
  "Return the outputs of every derivation that building ITEM needs and that
exist locally, leaving out downloads, whose content their derivation fixes."
  (match (valid-derivers store item)
    ((deriver _ ...)
     (filter (cut valid-path? store <>)
             (delete-duplicates
              (append-map (lambda (file)
                            (let ((drv (read-derivation-from-file file)))
                              (if (fixed-output-derivation? drv)
                                  '()
                                  (map cdr (derivation->output-paths drv)))))
                          (filter (cut string-suffix? ".drv" <>)
                                  (requisites store (list deriver)))))))
    (() (error "no derivation recorded for" item))))

(define (published-copies items)
  "Return (FARM ITEM HASH) for each of ITEMS that a farm publishes.  Guix
fetches this list without checking TLS certificates, so each entry must carry
the signature of the farm that serves it."
  (append-map
   (match-lambda
     ((farm key)
      (let ((acl (public-keys->acl (list (string->canonical-sexp key)))))
        (map (lambda (narinfo)
               (unless (valid-narinfo? narinfo acl)
                 (error "farm signature does not verify:" farm
                        (narinfo-path narinfo)))
               (list farm (narinfo-path narinfo)
                     (narinfo-hash->sha256 (narinfo-hash narinfo))))
             (lookup-narinfos (string-append "https://" farm) items)))))
   farms))

(define (verdict copies matching)
  "Classify a local store item from the farm COPIES of it and the farms whose
copy is the local one, MATCHING."
  (cond ((null? copies) 'unpublished)
        ((null? matching) 'mismatch)
        ((< (length matching) (length copies)) 'disputed)
        ((= (length matching) (length farms)) 'confirmed)
        (else 'one-farm)))

(with-store store
  (let* ((items (build-closure store (second (command-line))))
         (published (published-copies items))
         (results
          (map (lambda (item)
                 (let* ((local (path-info-hash (query-path-info store item)))
                        (copies (filter (match-lambda
                                          ((_ path _) (string=? path item)))
                                        published))
                        (matching (filter-map
                                   (match-lambda
                                     ((farm _ hash)
                                      (and (bytevector=? hash local) farm)))
                                   copies)))
                   (list (verdict copies matching) item matching)))
               items))
         (of-kind (lambda (kind)
                    (filter (match-lambda ((verdict . _) (eq? verdict kind)))
                            results))))
    (format #t "Guix packages used by the build: ~a match both farms, ~a match \
one farm while the other built different contents, ~a are on one farm only, ~a \
are on neither farm, and ~a match no farm.~%"
            (length (of-kind 'confirmed)) (length (of-kind 'disputed))
            (length (of-kind 'one-farm)) (length (of-kind 'unpublished))
            (length (of-kind 'mismatch)))
    (for-each (match-lambda
                ((kind . title)
                 (unless (null? (of-kind kind))
                   (format #t "~a:~%" title)
                   (for-each (match-lambda
                               ((_ item ()) (format #t "  ~a~%" item))
                               ((_ item (farm)) (format #t "  ~a from ~a~%" item farm)))
                             (of-kind kind)))))
              '((disputed . "The farms built different contents")
                (one-farm . "Only one farm publishes")
                (mismatch . "The local copy matches neither farm")))
    (exit (and (null? (of-kind 'mismatch)) (pair? published)))))
