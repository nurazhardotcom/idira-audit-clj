(ns pam-audit.idsvc-core
  "Portable translation from an idsvc inventory into the normalized estate
  shape consumed by the rule engine. Inventory HTTP remains native.")

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
