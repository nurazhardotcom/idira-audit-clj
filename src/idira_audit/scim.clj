(ns idira-audit.scim
  "SCIM-ish fetch layer: /Users, /Groups, /Tokens, /Policies.
   Plain GET + Bearer auth via bb's built-in http client. Response
   shapes are normalized to the maps idira-audit.rules expects — the
   normalization fns are pure and unit-tested without HTTP."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]))

(defn get-json
  "GET url with Bearer token; returns parsed body (keyword keys)."
  [base-url path token]
  (let [resp (http/get (str base-url path)
                       {:headers {"Authorization" (str "Bearer " token)
                                  "Accept" "application/json"}
                        :throw false})]
    (if (= 200 (:status resp))
      (json/parse-string (:body resp) true)
      (throw (ex-info (str "GET " path " failed")
                      {:status (:status resp) :body (:body resp)})))))

;; ---------- normalization (pure) ----------

(defn normalize-user [u]
  {:id (:userName u (:id u))
   :kind (keyword (or (:kind u) "human"))
   :active (if (contains? u :active) (boolean (:active u)) true)
   :owner-id (:ownerId u (:owner-id u))
   :mfa-enrolled (boolean (:mfaEnrolled u (:mfa-enrolled u)))
   :assurance (keyword (or (:assurance u) "none"))
   :vault-managed (boolean (:vaultManaged u (:vault-managed u)))
   :device-compliant (boolean (:deviceCompliant u (:device-compliant u)))
   :last-login (:lastLogin u (:last-login u))})

(defn normalize-group [g]
  {:id (:id g)
   :privileged (boolean (:privileged g))
   :members (vec (:members g))})

(defn normalize-token [t]
  {:id (:id t)
   :owner-id (:ownerId t (:owner-id t))
   :created (:created t)
   :revoked (boolean (:revoked t))})

(defn normalize-policy
  "Accept both wire (camelCase) and local (kebab-case) shapes."
  [p]
  {:require-mfa (boolean (:requireMfa p (:require-mfa p)))
   :min-assurance (keyword (or (:minAssurance p (:min-assurance p)) "none"))
   :require-adaptive-mfa (boolean (:requireAdaptiveMfa p (:require-adaptive-mfa p)))
   :require-device-posture (boolean (:requireDevicePosture p (:require-device-posture p)))
   :max-inactive-days (or (:maxInactiveDays p (:max-inactive-days p)) 90)
   :privileged-token-ttl-days (or (:privilegedTokenTtlDays p (:privileged-token-ttl-days p)) 180)
   :require-vaulting (boolean (:requireVaulting p (:require-vaulting p)))})

(defn fetch-estate
  "Pull the whole estate from a SCIM-compatible API. Returns
   {:users [...] :groups [...] :tokens [...] :policies {...}} in the
   normalized shape the rule engine consumes."
  [base-url token]
  {:users (mapv normalize-user (:Resources (get-json base-url "/scim/v2/Users" token)))
   :groups (mapv normalize-group (:Resources (get-json base-url "/scim/v2/Groups" token)))
   :tokens (mapv normalize-token (:Resources (get-json base-url "/api/v1/tokens" token)))
   :policies (normalize-policy (:policy (get-json base-url "/api/v1/policies/mfa" token)))})
