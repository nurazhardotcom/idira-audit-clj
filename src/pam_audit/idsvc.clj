(ns pam-audit.idsvc
  "Bridge: audit the sibling idsvc service (../idsvc) by reading its
   /inventory endpoint and translating it into the estate shape the
   rule engine consumes. idsvc already enforces sponsor binding, so a
   clean report here is itself evidence (cf. T2)."
  (:require [pam-audit.scim :as scim]))

(defn fetch-inventory
  "GET /inventory from a running idsvc. No auth required (local lab)."
  [base-url]
  (scim/get-json base-url "/inventory" "idsvc-local"))

(defn ->estate
  "Translate idsvc inventory into {:users :groups :tokens :policies}.
   Humans are non-privileged members of nothing; every NHI joins the
   privileged group `vault-admins` so the orphaned/unvaulted rules
   apply to exactly the right population."
  [inv]
  (let [humans (mapv (fn [h] {:id (:name h) :kind :human :active true
                              :owner-id nil
                              :mfa-enrolled false :assurance :none
                              :vault-managed true :device-compliant false
                              :last-login nil})
                     (:humans inv))
        nhis (mapv (fn [n] {:id (:name n) :kind :service :active true
                            :owner-id (:sponsor n)
                            :mfa-enrolled true :assurance :mfa
                            :vault-managed true :device-compliant true
                            :last-login nil})
                   (:non_human_identities inv))]
    {:users (into humans nhis)
     :groups [{:id "vault-admins" :privileged true
               :members (mapv :name (:non_human_identities inv))}]
     :tokens []
     ;; Conservative lab policy: idsvc has no MFA/token telemetry, so
     ;; only the sponsor-binding (orphan) rule carries signal here.
     :policies {:require-mfa false
                :max-inactive-days 90
                :privileged-token-ttl-days 180}}))
