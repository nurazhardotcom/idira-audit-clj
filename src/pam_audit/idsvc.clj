(ns pam-audit.idsvc
  "Bridge: audit the sibling idsvc service (../idsvc) by reading its
   /inventory endpoint and translating it into the estate shape the
   rule engine consumes. idsvc already enforces sponsor binding, so a
   clean report here is itself evidence (cf. T2)."
  (:require [pam-audit.idsvc-core :as idsvc-core]
            [pam-audit.scim :as scim]))

(defn fetch-inventory
  "GET /inventory from a running idsvc. No auth required (local lab)."
  [base-url]
  (scim/get-json base-url "/inventory" "idsvc-local"))

;; Compatibility var retained for existing native callers.
(def ->estate
  "Compatibility alias for the portable idsvc inventory translation."
  idsvc-core/->estate)
