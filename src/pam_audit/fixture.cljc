(ns pam-audit.fixture
  "Portable deterministic fixture data. This canonical EDN map is the
  source of truth; wire-shape conversion lives in pam-audit.wire.")

;; Fixed clock for determinism: 2026-09-05T00:00:00Z = 1788460800.
(def now-fixture 1788460800)

(def ^:private day 86400)

(defn- days-ago [n]
  (- now-fixture (* n day)))

(def estate-fixture
  {:users
   [{:id "ciso" :kind :human :active true :owner-id nil
     :mfa-enrolled true :assurance :adaptive-mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 1)}
    {:id "admin-active" :kind :human :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 2)}
    {:id "svc-orphan" :kind :service :active true :owner-id nil
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 2)}
    {:id "svc-dormant" :kind :service :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed true :device-compliant true
     :last-login (days-ago 120)}
    {:id "svc-unvaulted" :kind :service :active true :owner-id "ciso"
     :mfa-enrolled true :assurance :mfa
     :vault-managed false :device-compliant true
     :last-login (days-ago 3)}
    {:id "analyst-nomfa" :kind :human :active true :owner-id nil
     :mfa-enrolled false :assurance :none
     :vault-managed true :device-compliant false
     :last-login (days-ago 1)}]
   :groups
   [{:id "vault-admins" :privileged true
     :members ["admin-active" "svc-orphan" "svc-dormant" "svc-unvaulted"]}
    {:id "analysts" :privileged false
     :members ["analyst-nomfa" "ciso"]}]
   :tokens
   [{:id "tok-stale" :owner-id "svc-dormant"
     :created (days-ago 200) :revoked false}
    {:id "tok-fresh" :owner-id "admin-active"
     :created (days-ago 2) :revoked false}]
   :policies
   {:require-mfa true
    :min-assurance :mfa
    :require-adaptive-mfa true
    :require-device-posture true
    :max-inactive-days 90
    :privileged-token-ttl-days 180
    :require-vaulting true}})
