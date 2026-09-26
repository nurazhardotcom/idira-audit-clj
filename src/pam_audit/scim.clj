(ns pam-audit.scim
  "SCIM-ish fetch layer: /Users, /Groups, /Tokens, /Policies.
   Plain GET + Bearer auth via bb's built-in http client. Response
   shapes are normalized to the maps pam-audit.rules expects — the
   normalization fns are pure and unit-tested without HTTP."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [pam-audit.normalize :as normalize]))

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

;; Compatibility vars retained for existing native callers.
(def normalize-user normalize/normalize-user)
(def normalize-group normalize/normalize-group)
(def normalize-token normalize/normalize-token)
(def normalize-policy
  "Accept both wire (camelCase) and local (kebab-case) shapes."
  normalize/normalize-policy)

(defn fetch-estate
  "Pull the whole estate from a SCIM-compatible API. Returns
   {:users [...] :groups [...] :tokens [...] :policies {...}} in the
   normalized shape the rule engine consumes."
  [base-url token]
  {:users (mapv normalize-user (:Resources (get-json base-url "/scim/v2/Users" token)))
   :groups (mapv normalize-group (:Resources (get-json base-url "/scim/v2/Groups" token)))
   :tokens (mapv normalize-token (:Resources (get-json base-url "/api/v1/tokens" token)))
   :policies (normalize-policy (:policy (get-json base-url "/api/v1/policies/mfa" token)))})
