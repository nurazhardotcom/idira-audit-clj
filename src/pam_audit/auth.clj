(ns pam-audit.auth
  "Token acquisition: OAuth2 client-credentials grant or a static
   ISPSS-style API token. Uses bb's built-in babashka.http-client —
   no extra deps, native-image safe."
  (:require [babashka.http-client :as http]
            [cheshire.core :as json]
            [clojure.string :as str])
  (:import [java.util Base64]))

(defn- basic-auth [client-id client-secret]
  (let [raw (str client-id ":" client-secret)]
    (str "Basic " (.encodeToString (Base64/getEncoder) (.getBytes raw "UTF-8")))))

(defn- post-form
  "POST urlencoded form, returns parsed JSON body (or throws ex-info)."
  [url form-params headers]
  (let [body (->> form-params
                  (map (fn [[k v]] (str (name k) "=" v)))
                  (str/join "&"))
        resp (http/post url {:headers (merge headers
                                             {"Content-Type" "application/x-www-form-urlencoded"})
                             :body body
                             :throw false})]
    (if (= 200 (:status resp))
      (json/parse-string (:body resp) true)
      (throw (ex-info "token endpoint rejected request"
                      {:status (:status resp) :body (:body resp)})))))

(defn client-credentials-token
  "OAuth2 client-credentials flow. Returns the access token string.
   `cfg` = {:token-url ... :client-id ... :client-secret ... :scope ...}."
  [{:keys [token-url client-id client-secret scope]}]
  (:access_token
   (post-form token-url
              (cond-> {:grant_type "client_credentials"}
                scope (assoc :scope scope))
              {"Authorization" (basic-auth client-id client-secret)})))

(defn resolve-token
  "Return a bearer token from cfg: prefer :api-token (static ISPSS
   style), else run the client-credentials flow."
  [cfg]
  (or (:api-token cfg)
      (client-credentials-token cfg)))
